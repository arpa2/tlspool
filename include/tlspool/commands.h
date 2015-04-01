/* tlspool/commands.h -- Structure definitions for the UNIX socket protocol */


#ifndef TLSPOOL_COMMANDS_H
#define TLSPOOL_COMMANDS_H


#include <stdint.h>


#define TLSPOOL_IDENTITY_TMP	"20150313tlspool@tmp.vanrein.org"


/****************************** STRUCTURES *****************************/


#define TLSPOOL_CTLKEYLEN 16


/*
 * TLS Pool communication proceeds over a UNIX file system socket, by
 * sending and receiving messages like below.
 *
 * The order of events is always one where the application connecting
 * to the socket sends messages, and the TLS Pool always sends a response.
 * Depending on the command, this response may be fast or slow, but there
 * will always be a response as long as the connection is kept open.  If
 * the application can handle concurrent communication, it may send
 * more than one packet at a time.  The response will always copy the
 * pio_reqid field from the request to facilitate this; the application
 * should ensure different pio_reqid values for simultaneously sent
 * requests.  The TLS Pool may also request follow-up action, which
 * should also lead to exactly one action.  In this case, the pio_cbid
 * field must be copied into the new request.
 *
 * Command tags are 32 bit in size; this gives us the room to include
 * version numbers for semantic variations.  Implementations have the
 * freedom to combine similar tags (usually different versions) into
 * one piece of code.  Something counts as a version when its code has
 * been released into a code version; this does not include loose patches
 * or sheer uploads to a file system or mailing list.  Authors of new
 * versions are kindly requested to request an update to this file on its
 * prime location, http://github.com/vanrein/tlspool so it can serve as
 * a global registry, ensuring portability.
 * TODO: Consider changing to git.vanrein.org
 *
 * Commands would normally be deprecated for some time, i.e. recognised
 * but not sent.  After "sufficient time" has passed, a depracated tag
 * may be retracted from an implementation.  Instant retraction should
 * only be exercised under full control of all components, or for reasons
 * of urgency; notably, in case of security errors of the semantics (not
 * the coding) of a command tag.  This would effectively force other
 * components to upgrade -- but this is something to be careful about;
 * such upgrades should be readily available to all targeted users!
 *
 * It is generally safe to assume that applications need no protection
 * from the TLS Pool.  The opposite does not hold, as there are secrets
 * in the pool that may be interesting to attack.
 *
 * When a command fails, an error must always be reported through the
 * PIOC_ERROR_Vx command.  This is the only alternative to the usual
 * response, which may be PIOC_SUCCESS_Vx command or something defined
 * by the command to incorporate response data.
 *
 * Minute variations in commands should not be signaled with different
 * tags; instead, a flags field should be created in the payload.  This
 * is the more extensible approach.  Unknown flags are reserved for future
 * use and must always be set to zero when sending, and ignored when
 * receiving.  Such future extensions are always optional; a required
 * change would be implemented through a new semantics version.
 *
 * TODO: There may be extra pieces of information, notably the sending
 * of file descriptors is used to pass connections between processes.
 */


struct tlspool_command {
	uint16_t pio_reqid;	// Request->Response request identifier
	uint16_t pio_cbid;	// Response->Request callback identifier
	uint32_t pio_cmd;	// Command tag with semantic version
	union pio_data {
		struct pioc_error {
			int tlserrno;		// See <errno.h>
			char message [128];
		} pioc_error;
		struct pioc_ping {
			char YYYYMMDD_producer [8+128];	// when & who?
		} pioc_ping;
		struct pioc_starttls {
			uint32_t flags;		// PIOF_STARTTLS_xxx below
			uint32_t local;		// Locally defined bits
			uint8_t ipproto;	// IPPROTO_TCP, _UDP, _SCTP
			uint16_t streamid;	// Needed for SCTP
			char localid [128];	// Local ID or empty string
			char remoteid [128];	// Remote ID or empty string
			uint8_t ctlkey [TLSPOOL_CTLKEYLEN];	// Key for detach
		} pioc_starttls;
		struct pioc_pinentry {
			uint32_t flags;		// PIOF_PINENTRY_xxx below
			uint32_t attempt;	// Attempt counter -- display!
			uint32_t timeout_us;	// Timeout in microseconds
			char pin [128];		// Empty string means no PIN
			char prompt [128];	// Prompt from TLS Pool
			char token_manuf [33];	// PKCS #11 token manufacturer
			char token_model [17];	// PKCS #11 token model
			char token_serial [17];	// PKCS #11 token serial number
			char token_label [33];	// PKCS #11 token label
		} pioc_pinentry;
		struct pioc_control {
			uint32_t flags;		// PIOF_CONTROL_xxx, none yet
			uint8_t ctlkey [TLSPOOL_CTLKEYLEN]; // Control key
			char name [128];	// A name field
		} pioc_control;
	} pio_data;
};


typedef struct pioc_starttls starttls_t;


/******************************** COMMANDS *******************************/


/* An error packet is sent if the other party is unwilling to continue
 * the current exchange.  It explains why, through a code and message,
 * in the pioc_error type.  Error codes are defined in <errno.h>
 */
#define PIOC_SUCCESS_V1				0x00000000


/* An error packet is sent if the other party is unwilling to continue
 * the current exchange.  It explains why, through a code and message,
 * in the pioc_error type.  Error codes are defined in <errno.h>
 */
#define PIOC_ERROR_V1				0x00000001


/* A simple command to exchange courtesy, keepalives and potentially
 * identifying information of the peers.  The same packet is used in
 * both directions.
 * The string in pioc_ping.YYYYMMDD_producer describes the sender's
 * semantics with an identity comprising of a YYYYMMDD timestamp for
 * the software semantics version, plus a domain or user@domain identity
 * representing the producer at that time, terminated with '\0'.
 */
#define PIOC_PING_V1				0x00000010


/* Start a TLS sequence as a TLS client.  This uses PIO_STARTTLS_xxx
 * flags, defined below.  The local definitions of the TLS Pool define
 * part of the semantics.
 * The payload data is defined in pioc_starttls and is the same
 * for the client and server, and for request and response.  Clients
 * usually know the remoteid, and should fill that field instead of
 * leaving it an empty string.  They may already present their localid
 * or leave it open for possible interaction during the TLS exchange.
 */
#define PIOC_STARTTLS_CLIENT_V2			0x00000022


/* Start a TLS sequence as a TLS server.  This uses PIO_STARTTLS_xxx
 * flags, defined below.  The local definitions of the TLS Pool define
 * part of the semantics.
 * The payload data is defined in pioc_starttls and is the same
 * for the client and server, and for request and response.  Servers
 * do not always know the remoteid, and may set this to an empty string
 * to skip checking it.  They may not even know their localid if they
 * service many, so it is even possible to set that to an empty string
 * and leave it to the TLS exchange to propose localid values.
 */
#define PIOC_STARTTLS_SERVER_V2			0x00000023


/* When a client initiates TLS, it may have started off with an empty
 * string as its localid.  When a server serves a multitude of domains,
 * it may have done the same.  This can lead to a response by the TLS
 * daemon, proposing a localid that can be modified by the application
 * and sent back in the same message format.  The remoteid is sent
 * by the TLS Pool as extra information, but it is an empty string if
 * the information is unavailable.
 * Be prepared to receive zero or more of these proposals in the course
 * of a TLS exchange.  Especially when rejecting one localid there may
 * be ways for the TLS Pool to propose other localid values.
 * The payload used is the pioc_starttls, but only the localid and
 * remoteid are meaningful when sent by the TLS Pool, and only the
 * localid is interpreted when it returns to the TLS Pool.
 */
#define PIOC_STARTTLS_LOCALID_V1		0x00000028


/* TODO: Possibly support renegotiation, like for explicit authn */


/* The PIN entry command.  The data stored in tlscmd_pinentry determines
 * what happens exactly.  When sent to the TLS Pool it can provide a
 * non-empty PIN, which only makes sense in response to a PIOC_PINENTRY_V1
 * from the TLS Pool.  An empty PIN always means that no PIN is being
 * provided, possibly due to cancellation by the user.  All
 * token-descriptive are terminated with a NUL-character, unlike in
 * PKCS #11 where they have a fixed length.  Trailing spaces available
 * in the PKCS #11 level token description have been stripped off.
 */
#define PIOC_PINENTRY_V1			0x00000029


/* The named connect command.  This is used in callbacks from the TLS Pool,
 * to ask the application for a file descriptor.  Since this is called
 * after the TLS handshake has succeeded, there is no danger of leaking
 * information early; visibility and accessibility are usually arranged
 * through PIOC_STARTTLS_LOCALID_V1 and not here.  The use of this callback
 * is to provide a second file descriptor to the TLS Pool, and it is only
 * used when this has not been provided yet.  The information in the
 * tlsdata_t reflects localid and remoteid information from the handshake.
 */
#define PIOC_PLAINTEXT_CONNECT_V2		0x0000002a


/* Detach the connection decribed by the given ctlkey value.  The value for
 * each connection is provided by the client during the STARTTLS setup.
 * When the ctlkey is not found, an error is returned, otherwise SUCCESS.
 * See also the PIOF_STARTTLS_DETACH flag, which performs this action as part
 * of the STARTTLS setup.
 */
#define PIOC_CONTROL_DETACH_V2			0x00000100


/* Reattach a connection described by the given ctlkey value.  This can be
 * issued over any client connection to the TLS Pool to regain control over
 * a TLS/plaintext connection, but only if no controlling client is attached
 * yet.  The command returns an ERROR or SUCCESS.
 */
#define PIOC_CONTROL_REATTACH_V2		0x00000101


/* This command bit that marks a command as local.  Local commands are always
 * a bit of a risk, and should incorporate some way of identifying the
 * source of the command, or would otherwise be wise to exercise complete
 * control over the visibility of the extension code.  Picking rather
 * arbitrary codes may also help somewhat.
 */
#define PIOC_LOCAL				0x80000000


/********************************* FLAGS ********************************/


/* PIOF_STARTTLS_xxx flags are sent and received in pioc_starttls.
 *
 * When sent to the TLS Pool, they may provide it some freedom; when
 * it is still set in the response then this freedom has been exercised.
 *
 * Other flags indicate additional requirements.  When these are not met,
 * an error will be raised.  Their meaning in the response is meaningless.
 */


/* PIOF_STARTTLS_DTLS requests to setup DTLS instead of TLS.
 */
#define PIOF_STARTTLS_DTLS			0x00000001


/* PIOF_STARTTLS_REQUIRE_DNSSEC tells the TLS Pool that DNSSEC must be
 * used for all information in DNS; so, a self-acclaimed I-can-do-without
 * domain is no longer permitted to connect over TLS.  The TLS Pool may
 * rely on an external resolver to properly set the AD bits.
 */
#define PIOF_STARTTLS_REQUIRE_DNSSEC		0x00000010


/* PIOF_STARTTLS_TIGHTEN_LDAP tells the TLS Pool that LDAP connections must
 * be secured through TLS.  In addition, the certificate used by LDAP will
 * be verified as is normally done for domain certificates.  Normally, that
 * means it must be acknowledged in a TLSA record.  Users and domains from
 * LDAP servers that do not live up to this are no longer trusted as peers
 * on grounds of their occurrence in LDAP alone.
 */
#define PIOF_STARTTLS_REQUIRE_LDAP_CERT		0x00000020
#define PIOF_STARTTLS_REQUIRE_LDAP_DANE		0x00000040
#define PIOF_STARTTLS_REQUIRE_LDAP_SECURITY	0x00000060


/* PIOF_STARTTLS_SKIP_EXT_AUTHN tells the TLS Pool that no external
 * authentication is needed on top of the normal operations of the
 * TLS Pool.  Usually, if an external authentication source is configured,
 * it will be RADIUS.  If it is not even configured, then this flag is of
 * no consequence.
 */
#define PIOF_STARTTLS_SKIP_EXT_AUTHN		0x00000080


/* PIOF_STARTTLS_SKIP_EXT_AUTHZ tells the TLS Pool that no external
 * authorization is needed on top of the normal operations of the
 * TLS Pool.  Usually, if an external authorization source is configured,
 * it will be RADIUS.  If it is not even configured, then this flag is of
 * no consequence.
 */
#define PIOF_STARTTLS_BYPASS_EXT_AUTHZ		0x00000100


/* PIOF_STARTTLS_SEND_SNI can be used for client-side STARTTLS as an
 * indication that the remotid is present and its domain should be
 * passed over to the other side as a Server Name Indication.  This
 * is not a common structure for all protocols, but it is harmless
 * because it is an indicative TLS option.  Note that it is useful
 * of xxxxs: protocols, which immediately start TLS, but usually not
 * needed for protocols that issue a STARTTLS command during a normal
 * exchange.  Anyhow, this is application-determined. 
 * If the remoteid contains a user@ part, it is not sent as part of
 * the SNI information, because that would violate the format.  It
 * is a missed opportunity though.
 */
#define PIOF_STARTTLS_SEND_SNI			0x00000200


/* PIOF_STARTTLS_IGNORE_CACHES requires the TLS Pool to perform the
 * validation here and now.  It will not accept cached results from
 * recent encounters as sufficient proof that the remote peer has
 * the acclaimed identity.  This can be used at places in an
 * interaction where the identity of the remote peer must be firmly
 * established.  Note that bypassing the caches dramatically increases
 * the amount of work for the TLS Pool, and should thus be used with
 * care.  Note that the validation outcome may still be cached, for
 * future use when the peer relation is more relaxed.
 */
#define PIOF_STARTTLS_IGNORE_CACHES		0x00000400


/* PIOF_STARTTLS_REQUEST_REMOTEID means that the TLS Pool should not
 * strictly require, but merely request a remote identity.  This is
 * useful if the remote peer is a client who may not have a certificate
 * to authenticate with, and should still be able to access the service
 * over TLS.  It is also useful to permit anonymous TLS connections to
 * remote clients or servers if both sides agree to that.
 * Note that a bidirectionally unauthenticated TLS connection is not
 * protected from man in the middle attacks, although it does warrant
 * against passive observers.
 */
#define PIOF_STARTTLS_REQUEST_REMOTEID		0x00000800


/* PIOF_STARTTLS_IGNORE_REMOTEID means that the TLS Pool need not bother
 * to even request a remote identity.  If one is provided, it is not
 * validated.  This is useful if the local application cannot use the
 * remote identity in any useful way.  It is also useful to permit
 * anonymous TLS connections to remote clients or servers if both sides
 * agree to that.
 * Note that a bidirectionally unauthenticated TLS connection is not
 * protected from man in the middle attacks, although it does warrant
 * against passive observers.
 */
#define PIOF_STARTTLS_IGNORE_REMOTEID		0x00001000


/* PIOF_STARTTLS_DETACH instructs the TLS Pool to detach the TLS session
 * from the client connection over which it was setup.  This means that
 * no more control commands can be sent in relation to the TLS session
 * until a client connection issues a successful PIOC_CONTROL_REATTACH_V2.
 * 
 * In many applications, this flag will be combined with PIOF_STARTTLS_FORK
 * which has an independent meaning; FORK applies to the independent
 * life of a TLS session that is run by the TLS Pool, and DETACH applies to
 * the ability to send control commands in relation to a TLS session.
 *
 * The TLS Pool also implements one relationship between FORK and DETACH;
 * after a FORK, the close-down of the client that setup a connection will
 * automatically cause a DETACH of those TLS sessions.
 *
 * When the PIOC_STARTTLS_xxx exchange starts, the value in ctlkey is stored
 * fur future reference; control can be regained from any TLS Pool client
 * connection that presents the ctlkey in PIOC_CONTROL_REATTACH_V2.
 *
 * See also the PIOC_CONTROL_DETACH_V2 command, which performs the action as
 * a separate command.
 */
#define PIOF_STARTTLS_DETACH			0x00002000


/* PIOF_STARTTLS_FORK instructs the TLS Pool that the TLS session should
 * continue to run when the client connection over which it was setup closes.
 * By default, TLS sessions are terminated when their requesting client
 * disappears, for instance due to termination of the requesting program.
 *
 * FORK and DETACH are different concepts; FORK applies to the independent
 * life of a TLS session that is run by the TLS Pool, and DETACH applies to
 * the ability to send control commands in relation to a TLS session.  Many
 * applications will use the two combined.  The TLS Pool also implements one
 * relation; after a FORK, the close-down of the client that setup a
 * connection will automatically cause a DETACH of those TLS sessions.
 */
#define PIOF_STARTTLS_FORK			0x00004000


#endif //TLSPOOL_COMMANDS_H

