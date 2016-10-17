/* tlspool/commands.h -- Structure definitions for the UNIX socket protocol */


#ifndef TLSPOOL_COMMANDS_H
#define TLSPOOL_COMMANDS_H

#ifdef __cplusplus
extern "C"
{
#endif

#include <stdint.h>

#ifdef WINDOWS_PORT
#define _usleep(usec) (Sleep((usec) / 1000))
#define poll(fds, nfds, timeout) WSAPoll(fds, nfds, timeout)
#include <winsock2.h>
#else /* WINDOWS_PORT */
#define _usleep(usec) usleep(usec)
#endif /* WINDOWS_PORT */


#define TLSPOOL_IDENTITY_V2	"20151111api@tlspool.arpa2.net"


/****************************** STRUCTURES *****************************/


#define TLSPOOL_CTLKEYLEN 16
#define TLSPOOL_SERVICELEN 16
#define TLSPOOL_PRNGBUFLEN 350
#define TLSPOOL_TIMEOUT_DEFAULT 0
#define TLSPOOL_TIMEOUT_INFINITE (~(uint32_t)0)

#ifdef WINDOWS_PORT
/* Windows is the only non-POSIX system, and as such, it is the only
 * platform that does not support ancilary data (as on UNIX domain sockets).
 * To pass a socket or file handle, different structures must be passed to
 * the TLS Pool, and of course it is also possible to pass neither.  The
 * anciltype indicates which applies.  This is used in an add-on that is
 * always appended to the TLS Pool structure when passing it on Windows.
 */
enum anciltype {
	ANCIL_TYPE_NONE = 0,
	ANCIL_TYPE_SOCKET = 1,
	ANCIL_TYPE_FILEHANDLE = 2,
};
#endif /* WINDOWS_PORT */


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

#pragma pack(push,2)

struct pioc_error {
	int tlserrno;			// See <errno.h>
	char message [128];
};

struct pioc_ping {
	char YYYYMMDD_producer [8+128];	// when & who?
	uint32_t facilities;		// PIOF_FACILITY_xxx
};

struct pioc_starttls {
	uint32_t flags;			// PIOF_STARTTLS_xxx below
	uint32_t local;			// Locally defined bits
	uint8_t ipproto;		// IPPROTO_TCP, _UDP, _SCTP
	uint16_t streamid;		// Needed for SCTP
	char localid [128];		// Local ID or empty string
	char remoteid [128];		// Remote ID or empty string
	uint8_t ctlkey [TLSPOOL_CTLKEYLEN];	// Key for detach
	uint8_t service [TLSPOOL_SERVICELEN];	// Names from IANA
	uint32_t timeout;		// in ms, 0=default, ~0=infinite
};

struct pioc_pinentry {
	uint32_t flags;			// PIOF_PINENTRY_xxx below
	uint32_t attempt;		// Attempt counter -- display!
	uint32_t timeout_us;		// Timeout in microseconds
	char pin [128];			// Empty string means no PIN
	char prompt [128];		// Prompt from TLS Pool
	char token_manuf[32 + 1 + 3];	// PKCS #11 token manufacturer
	char token_model[16 + 1 + 3];	// PKCS #11 token model
	char token_serial[16 + 1 + 3];	// PKCS #11 token serial number
	char token_label[32 + 1 + 3];	// PKCS #11 token label
};

struct pioc_lidentry {
	uint32_t flags;			// PIOF_LIDENTRY_xxx below
	uint16_t maxlevels;		// Max # iterations for concrete ID
	uint32_t timeout;		// Regtimeout[s] or resptimeout
	char localid [128];		// Local ID or empty string
	char remoteid [128];		// Remote ID or empty string
};

struct pioc_control {
	uint32_t flags;			// PIOF_CONTROL_xxx, none yet
	uint8_t ctlkey [TLSPOOL_CTLKEYLEN]; // Control key
	char name [128];		// A name field
};

struct pioc_prng {
	int16_t in1_len, in2_len, prng_len;
	uint8_t buffer [TLSPOOL_PRNGBUFLEN]; // ctlkey, in1, in2
};

struct tlspool_command {
	uint16_t pio_reqid;	// Request->Response request identifier
	uint16_t pio_cbid;	// Response->Request callback identifier
	uint32_t pio_cmd;	// Command tag with semantic version
	union pio_data {
		struct pioc_error pioc_error;
		struct pioc_ping pioc_ping;
		struct pioc_starttls pioc_starttls;
                struct pioc_pinentry pioc_pinentry;
                struct pioc_lidentry pioc_lidentry;
		struct pioc_control pioc_control;
		struct pioc_prng pioc_prng;
	} pio_data;
#ifdef WINDOWS_PORT
	union { HANDLE hPipe; uint64_t _pad1; };
	enum anciltype pio_ancil_type;
	union pio_ancil_data {
		HANDLE pioa_filehandle;
		WSAPROTOCOL_INFOW pioa_socket;
	} pio_ancil_data;
#endif
};
#pragma pack(pop)


typedef struct pioc_ping     pingpool_t;
typedef struct pioc_starttls starttls_t;
typedef struct pioc_pinentry pinentry_t;
typedef struct pioc_lidentry lidentry_t;


/******************************** COMMANDS *******************************/


/* An error packet is sent if the other party is unwilling to continue
 * the current exchange.  It explains why, through a code and message,
 * in the pioc_error type.  Error codes are defined in <errno.h>
 */
#define PIOC_SUCCESS_V2				0x00000000


/* An error packet is sent if the other party is unwilling to continue
 * the current exchange.  It explains why, through a code and message,
 * in the pioc_error type.  Error codes are defined in <errno.h>
 */
#define PIOC_ERROR_V2				0x00000001


/* A simple command to exchange courtesy, keepalives and potentially
 * identifying information of the peers.  The same packet is used in
 * both directions.
 *
 * The string in pioc_ping.YYYYMMDD_producer describes the sender's
 * semantics with an identity comprising of a YYYYMMDD timestamp for
 * the software semantics version, plus a domain or user@domain identity
 * representing the producer at that time, terminated with '\0'.
 *
 * The facilities make it possible to ask the TLS Pool which extended
 * facilities will be supported.  The compile-time constant
 * PIOF_FACILITY_ALL_CURRENT is usually sent to the TLS Pool, which
 * will only reset bits from what it receives.  The default behaviour
 * is a bit-wise and with the TLS Pool's own PIOF_FACILITY_ALL_CURRENT
 * but configuration may lead to a further reduction of usable
 * facilities.
 */
#define PIOC_PING_V2				0x00000010


/* Start a TLS handshake.  This uses PIO_STARTTLS_xxx flags, defined below.
 * One of the things these flags set is the acceptable roles of the local
 * and remote node -- client, server or peer (for which both are acceptable).
 * The local definitions of the TLS Pool define part of the semantics.
 *
 * The payload data is defined in pioc_starttls and is the same
 * for clients, servers and peers, and for request and response.  Clients
 * usually know the remoteid, and should fill that field instead of
 * leaving it an empty string.  They may already present their localid
 * or leave it open for possible interaction during the TLS exchange.
 */
#define PIOC_STARTTLS_V2			0x00000024


/* When a client initiates TLS, it may have started off with an empty
 * string as its localid.  When a server serves a multitude of domains,
 * it may have done the same.  This can lead to a response by the TLS
 * daemon, proposing a localid that can be modified by the application
 * and sent back in the same message format.  The remoteid is sent
 * by the TLS Pool as extra information, but it is an empty string if
 * the information is unavailable.
 *
 * Various sources may supply a local identity; it may arrive in a
 * Server Name Indication over TLS, it may be suggested by the disclose.db
 * with potentially registered LIDENTRY extension.  The outcome of these
 * sources is presented through this command.
 *
 * This callback is only made when PIOF_STARTTLS_LOCALID_CHECK is set.
 * Then, be prepared to receive zero or more of these proposals in the course
 * of a TLS handshake.  Especially when rejecting one localid there may
 * be ways for the TLS Pool to propose other localid values.
 * The payload used is the pioc_starttls, but only the localid and
 * remoteid are meaningful when sent by the TLS Pool, and only the
 * localid is interpreted when it returns to the TLS Pool.  In all these
 * identity strings, the empty string is used to indicate absense of an
 * acceptable value.
 *
 * When this callback passes a file descriptor to the TLS Pool, it will be
 * interpreted as the plaintext file descriptor and an implied acceptance
 * of the local identity presented, regardless of the localid returned.
 */
#define PIOC_STARTTLS_LOCALID_V2		0x00000028


/* The PIN entry command.  The data stored in tlscmd_pinentry determines
 * what happens exactly.  When sent to the TLS Pool it can provide a
 * non-empty PIN, which only makes sense in response to a PIOC_PINENTRY_V2
 * from the TLS Pool.  An empty PIN always means that no PIN is being
 * provided, possibly due to cancellation by the user.  All
 * token-descriptive are terminated with a NUL-character, unlike in
 * PKCS #11 where they have a fixed length.  Trailing spaces available
 * in the PKCS #11 level token description have been stripped off.
 */
#define PIOC_PINENTRY_V2			0x00000029


/* The named connect command.  This is used in callbacks from the TLS Pool,
 * to ask the application for a file descriptor.  Since this is normally called
 * after the TLS handshake has succeeded, there is no danger of leaking
 * information early; visibility and accessibility are usually arranged
 * through PIOC_LIDENTRY_xxx callbacks or the disclose.db but not here.  See
 * PIOF_STARTTLS_LOCALID_CHECK for an earlier, optional callback with
 * PIOC_STARTTLS_LOCALID_V2 though.
 *
 * The use of this callback is to provide a second file descriptor to the
 * TLS Pool, and it is called exactly once as part of a successful TLS
 * connection setup.  The information in the tlsdata_t reflects localid and
 * remoteid information from the handshake.
 */
#define PIOC_PLAINTEXT_CONNECT_V2		0x0000002a


/* Generate a pseudo-random sequence based on session cryptographic keys.
 * In the case of TLS, this adheres to RFC 5705; other protocols may or
 * may not support a similar mechanism, in which case an error is returned.
 *
 * This leans on access privileges to an existing connection at a meta-level,
 * for which we use the customary ctlkey verification mechanism.  Note that
 * random material may be used for security purposes, such as finding the
 * same session key for both sides deriving from prior key negotiation; the
 * protection of a ctlkey for such applications is important.
 *
 * This command provides a struct pioc_prng holding the following information:
 *  - in1_len, in2_len hold lengths < 255 with input strings
 *  - buffer holds the ctlkey and then in1_len + in2_len bytes of input data
 *  - negative values in in1_len and/or in2_len suppress that field
 *  - prng_len holds the requested number of pseudo-random bytes
 *
 * If the operation succeeds, a struct_pioc_prng is returned holding:
 *  - prng_len holds the provided number of pseudo-random bytes
 *  - buffer holds these bytes (and has overwritten the rest of the buffer)
 *
 * The RFC 5705 implementation for TLS specifically uses:
 *  - in1_len is the length of the exporter label
 *  - in2_len is negative for no context or it is a context length
 *
 * Note a few restrictions to the generality of this operation:
 *  - it limits the input sizes
 *  - it limits the retrievable pseuo-random data to a prefix
 *
 * The TLS Pool may limit certain TLS PRNG labels, in adherence to the
 * IANA-maintained TLS Exporter Label Registry.  It additionally supports
 * the EXPERIMENTAL label prefix specified in RFC 5705.
 *
 * Be advised that the size of buffer may increase in future releases.  So,
 * be sure to use TLSPOOL_PRNGBUFLEN which holds the header-file defined size.
 */
#define PIOC_PRNG_V2				0x0000002b


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


/* Register a LIDENTRY extension with the given flags to indicate the desired
 * callbacks.  Only one application may register for such callbacks, and the
 * registration will provide callbacks for as long as the connection to the
 * TLS Pool is kept alive.  The command never returns; it provides callbacks.
 *
 * The data field for this command is pioc_lidentry, of which only the flags
 * are interpreted; and of those, only the ones that impact registration.
 *
 * Presently, callbacks may be expected to follow a sequence, where zero or
 * more database entries may be sent preceding the actual callback that asks
 * for the desired localid to use.  This means that other TLS handshakes that
 * desire to be in the same sequence are locked out, and that may be overruled
 * at a later time, if we need to provide better interaction.
 */
#define PIOC_LIDENTRY_REGISTER_V2		0x00000200


/* Callback to the LIDENTRY extension, as well as its non-ERROR responses, use
 * the PIOC_LIDENTRY_CALLBACK_V2 command with the pioc_lidentry data format.
 */
#define PIOC_LIDENTRY_CALLBACK_V2		0x00000201


/* This command bit that marks a command as local.  Local commands are always
 * a bit of a risk, and should incorporate some way of identifying the
 * source of the command, or would otherwise be wise to exercise complete
 * control over the visibility of the extension code.  Picking rather
 * arbitrary codes may also help somewhat.
 */
#define PIOC_LOCAL				0x80000000


/*************************** PIOF_FACILITY_xxx FLAGS **************************/


/* The PIOF_FACILITY_xxx facilities are sent and received in pioc_ping.
 *
 * When sent to the TLS Pool, this expresses the facilities that the
 * application is interested in.  A customary practice is to set this
 * to PIOF_FACILITY_ALL_CURRENT to incorporate all the compile-time
 * facilities known to the TLS Pool client.
 *
 * The TLS Pool will respond by resetting those facilities that it will
 * not support.  This may be due to the PIOF_FACILITY_ALL_CURRENT at the
 * time it was built, or to explicit configuration that denies certain
 * facilities and/or that only allows certain other facilities.
 *
 * The facilities that are currently specified, though not necessarily
 * implemented and incorporated into PIOF_FACILITY_ALL_CURRENT, are:
 *
 * PIOF_FACILITY_STARTTLS -- support for the PIOC_STARTTLS command
 * PIOF_FACILITY_STARTGSS -- support for the PIOC_STARTGSS command
 * PIOF_FACILITY_STARTSSH -- support for the PIOC_STARTSSH command
 *
 * Note that the interpretation of flags sent from the TLS Pool, as well
 * as those sent to the TLS Pool, are subject to the API version that is
 * reported by the the PING command.
 */

#define PIOF_FACILITY_ALL_CURRENT		0x00000001
#define PIOF_FACILITY_STARTTLS			0x00000001
#define PIOF_FACILITY_STARTGSS			0x00000002
#define PIOF_FACILITY_STARTSSH			0x00000004


/*************************** PIOF_STARTTLS_xxx FLAGS **************************/


/* PIOF_STARTTLS_xxx flags are sent and received in pioc_starttls.
 *
 * When sent to the TLS Pool, they may provide it some freedom; when
 * it is still set in the response then this freedom has been exercised.
 *
 * Other flags indicate additional requirements.  When these are not met,
 * an error will be raised.  Their meaning in the response is meaningless.
 */


/* PIOF_STARTTLS_xxxROLE_xxx flags define whether the local or remote should
 * act as a client or as a server.  This is the TLS relationship, and may or
 * may not match the transport connection over which TLS runs.
 *
 * Each side may be setup to act as a peer, which means it will mirror the
 * other side.  When either side is setup as a peer, the TLS Pool will begin
 * as a client, but employ a TLS extension that can ignore the ClientHello
 * from one of the sides -- this is not currently a part of TLS, but may be
 * added later on, in support of peer-to-peer connections as drafted in
 * draft-vanrein-tls-p2p.
 *
 * At some point, the TLS transaction has an obvious client and server side,
 * even in peer-to-peer connections, and a normal handshake commences.  But
 * the remote role helps to decide which forms of identity are acceptable,
 * and when a remote peer effectively became a server it may still present
 * a client credential, and the similar freedom may also be assumed by the
 * local side, although the "right" kind of credential is preferred.
 */

#define PIOF_STARTTLS_LOCALROLE_CLIENT		0x00000001
#define PIOF_STARTTLS_LOCALROLE_SERVER		0x00000002
#define PIOF_STARTTLS_LOCALROLE_PEER		0x00000003

#define PIOF_STARTTLS_REMOTEROLE_CLIENT		0x00000004
#define PIOF_STARTTLS_REMOTEROLE_SERVER		0x00000008
#define PIOF_STARTTLS_REMOTEROLE_PEER		0x0000000c

#define PIOF_STARTTLS_BOTHROLES_PEER		0x0000000f


/* PIOF_STARTTLS_DTLS requests to setup DTLS instead of TLS.
 */
#define PIOF_STARTTLS_DTLS			0x00000100


/* PIOF_STARTTLS_WITHOUT_SNI can be used for client-side STARTTLS as an
 * indication that if the remotid is present then its domain should not
 * be passed over to the other side as a Server Name Indication.  This
 * is not a common structure for all protocols, but is sent by default
 * because it is an indicative TLS option.  Note that it is useful
 * for xxxxs: protocols, which immediately start TLS, but usually not
 * needed for protocols that issue a STARTTLS command during a normal
 * exchange.  Anyhow, this is application-determined. 
 * If the remoteid contains a user@ part, it is not sent as part of
 * the SNI information, because that would violate the format.  That
 * is a missed opportunity though.
 */
#define PIOF_STARTTLS_WITHOUT_SNI		0x00000200


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
 *
 * Note that a bidirectionally unauthenticated TLS connection is not
 * protected from man in the middle attacks, although its encryption
 * may protect against passive observers.
 *
 * This flag is overridden by PIOF_STARTTLS_IGNORE_REMOTEID.
 */
#define PIOF_STARTTLS_REQUEST_REMOTEID		0x00000800


/* PIOF_STARTTLS_IGNORE_REMOTEID means that the TLS Pool need not bother
 * to even request a remote identity.  If one is provided, it is not
 * validated.  This is useful if the local application cannot use the
 * remote identity in any useful way.  It is also useful to permit
 * anonymous TLS connections to remote clients or servers if both sides
 * agree to that.
 *
 * Note that a bidirectionally unauthenticated TLS connection is not
 * protected from man in the middle attacks, although it does warrant
 * against passive observers.
 *
 * This flag overrides PIOF_STARTTLS_REQUEST_REMOTEID.
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


/* PIOF_STARTTLS_DOMAIN_REPRESENTS_USER indicates that the remote identity
 * need not be the expected user@domain, but that the domain is acceptable
 * as well.  This is a common flag on protocols such as SMTP, where a
 * server represents all users under its domain, and authenticates as the
 * domain instead of as the user.  Note that the flag applies equally well
 * to clients as it does to servers.  If an application does not supply
 * this flag, it must supply any remote_id field for a STARTTLS exchange in
 * the exact format as it is supported by the server.  The returned remote_id
 * will always be the exact identity as provided by the server.
 */
#define PIOF_STARTTLS_DOMAIN_REPRESENTS_USER	0x00008000


/* PIOF_STARTTLS_LOCALID_CHECK requests that a local identity is provided
 * to the application before it is accepted; this mechanism allows the
 * application to check such things as its list of virtual host names, and
 * whether these can be served.  When this flag is set, the callback command
 * PIOC_STARTTLS_LOCALID_V2 is sent before presenting the local identity.
 * The local identity that is being checked is the outcome from the disclose.db
 * with possible extensions by a registered LIDENTRY extension.
 */
#define PIOF_STARTTLS_LOCALID_CHECK		0x00010000


/* PIOF_STARTTLS_RENEGOTIATE takes a previously agreed TLS connection and
 * renegotiates identities as specified in this STARTTLS request.  The
 * ctlkey field indicates an attached TLS connection that is to be
 * renegotiated; this field will not be modified in the course of this
 * run of the STARTTLS command.
 */
#define PIOF_STARTTLS_RENEGOTIATE		0x00020000


/* PIOF_STARTTLS_LOCALID_ONTHEFLY indicates that the localid credentials in the
 * STARTTLS request should be generated on the fly.  This may restrict the number
 * of technologies available, and it usually requires the remote end to accept
 * certificates signed by the TLS Pool, usually under a signing key/certificate
 * as setup in etc/tlspool.conf with tls_onthefly_signcert and _signkey.  Note
 * that if these are not configured, the STARTTLS request will usually fail.
 */
#define PIOF_STARTTLS_LOCALID_ONTHEFLY		0x00040000



/*************************** PIOF_LIDENTRY_xxx FLAGS **************************/


/* The flags below set the behaviour while searching the disclose.db for entries
 * that map a remote identity to a list of local identities.  It indicates which
 * values may be passed without interaction by the LIDENTRY extension; by
 * default, the registration of a LIDENTRY extension implies that all attempts
 * to determine a local identity pass through the extension; the _SKIP_ flags
 * indicate which entries may be implicitly skipped when they *all* apply.
 *
 * PIOF_LIDENTRY_SKIP_USER indicates that part of the skip condition is that
 * any username is not removed; variants with just a domain name are also
 * considered skippable under this flag;
 *
 * PIOF_LIDENTRY_SKIP_DOMAIN_xxx indicates whether the domain may be changed;
 * use _SAME and/or _ONEUP to indicate 0 and 1 levels up from the concrete
 * domain name; the _SUB variation combines _SAME and _ONEUP.
 *
 * PIOF_LIDENTRY_SKIP_NOTROOT indicates that the entry must not be the root
 * domain entry; whether or not the username is removed is not of influence
 * on the meaning of this flag.
 *
 * PIOF_LIDENTRY_SKIP_DBENTRY indicates that the entry must be in the database;
 * it is implied by all the above, but has meaning when used on its own, as it
 * permits skipping anything that is stored, without further restricting flags.
 *
 * These flags are used while registering a LIDENTRY extension; they are also
 * returned in callbacks, where they refer to the remote identity selector.
 * For example, _SKIP_USER indicates that the username part was skipped, and
 * _SKIP_DOMAIN_ONEUP indicates that the domain name goes one up.
 *
 * Although the skip selection could be made in the extension, it is less
 * efficient that way; the interaction with the extension is forced into a
 * sequence, and concurrent contenders may therefore need to wait for the
 * extension while it is interacting with the user.  So, skipping user
 * interaction when it is not needed is advantageous.  When skipping, the
 * disclose.db is used as a source, as if the LIDENTRY extension was not
 * registered at all.
 */
#define PIOF_LIDENTRY_SKIP_DBENTRY		0x00000080 /* in all _SKIP_ */
#define PIOF_LIDENTRY_SKIP_USER			0x00000081
#define PIOF_LIDENTRY_SKIP_DOMAIN_SAME		0x00000082
#define PIOF_LIDENTRY_SKIP_DOMAIN_ONEUP		0x00000084
#define PIOF_LIDENTRY_SKIP_DOMAIN_SUB		0x00000086 /* _SAME | _ONEUP */
#define PIOF_LIDENTRY_SKIP_NOTROOT		0x00000088


/* PIOF_LIDENTRY_LIST_DBENTRY is used as a flag during PIOC_LIDENTRY_REGISTER_V2
 * and will cause PIOC_LIDENTRY_CALLBACK_V2 callbacks for database entries at
 * the most concrete level above the considered remoteid.
 *
 * Any such database entry callbacks precede the normal callback and have:
 *  - PIOF_LIDENTRY_DBENTRY set
 *  - maxlevels set to the number of levels up for this entry (0 for concrete)
 *  - remoteid set to the remoteid entry found in disclose.db
 *  - localid set to an entry found in the database
 * The return from the callback should not be ERROR but is otherwise ignored.
 *
 * The final/normal callback is different:
 *  - PIOF_LIDENTRY_DBENTRY is not set
 *  - maxlevels set to the number of permissible levels up (from 0 for concrete)
 *  - remoteid set to the concrete remote identity considered
 *  - localid set to the application-suggested local identity, or empty=undef
 * The return value from the callback should be PIOC_LIDENTRY_CALLBACK and have:
 *  - flags can hold PIOF_LIDENTRY_xxx flags suitable for callback processing
 *  - remoteid is the given concrete, or no more than maxlevels iterations up
 *  - localid is the concrete identity to disclose, unrelated to the suggested
 */
#define PIOF_LIDENTRY_WANT_DBENTRY		0x00000100
#define PIOF_LIDENTRY_DBENTRY			0x00001000


/* The mask PIOF_LIDENTRY_REGFLAGS is used to mask the flags that will be
 * reproduced in the callback flags, and should be left alone by applications
 * as these flags will be used during re-registration.  Note that this must
 * pass through the callback interface, because the re-registration may occur
 * after a timeout and should then ideally behave the same (if not overtaken
 * by another process) as a timely re-registration.  Modification of these
 * flags in the callback in case of timely callback is undefined and any
 * reliance of that is subject to possible future breakage without warning.
 */
#define PIOF_LIDENTRY_REGFLAGS			0x00000fff


/* PIOF_LIDENTRY_DBAPPEND and PIOF_LIDENTRY_DBINSERT indicate that the provided
 * information should be added to the database, respectively at the end or
 * beginning of the disclose.db list of local identities for the given remote
 * identity.  When the entry is already available, the posision is not changed
 * by default, but that will be done when PIOF_LIDENTRY_DBREORDER is set.
 *
 * Changes to the database are part of a database transaction that is rolled
 * back when the TLS handshake fails.  This means that providing an identity
 * that somehow fails to work is not going to be remembered for the next time.
 * A simple restart of the TLS handshake therefore suffices to restart the
 * user interaction and find an alternative.  Note that it is assumed that the
 * application that uses the TLS Pool will somehow report back on the failure,
 * and the user should therefore not be surprised to be confronted with a
 * question that he though had been stored.
 *
 * Note that these flags lead to database activity; optimal efficiency
 * requires that they are only set on PIOF_LIDENTRY_CALLBACK_V2 responses
 * that actually write to the database -- because they return either:
 *  - a remoteid less than maxlevels steps up with _DBINSERT/_DBAPPEND
 *  - a localid with _DBINSERT/_DBAPPEND if it is not yet setup in the database
 *  - a localid whose position must be updated under _DBREORDER
 */
#define PIOF_LIDENTRY_DBINSERT			0x00002000
#define PIOF_LIDENTRY_DBAPPEND			0x00004000
#define PIOF_LIDENTRY_DBREORDER			0x00008000


/* PIOF_LIDENTRY_NEW indicates in a response to a callback that the selected
 * local identity should be available soon, but may not have come through yet.
 * It instructs the TLS Pool to await its arrival before proceeding.
 *
 * This flag is useful to end a callback (and thus free up the resource of the
 * forced user-interaction sequence) while identities are being created in
 * complex network infrastructures that may involve key generation, publication
 * in identity showcases like DNS or LDAP, and whatever else is needed to have
 * identities embedded in an infrastructure.
 *
 * TODO: This is unimplemented behaviour; the flag is merely allocated.
 * The result of using this is currently immediate return of DB_NOTFOUND.
 */
#define PIOF_LIDENTRY_NEW			0x00100000


/* PIOF_LIDENTRY_ONTHEFLY indicates in a response to callback that the selected
 * local identity should be setup as an on-the-fly identity.  This type of
 * identity is only available locally, and uses a configured credential to
 * vouch for the on-the-fly generated identity.  The manner in which this
 * is done depends on the kind of credential to provide.
 *
 * These on-the-fly identities will disappear when the TLS Pool restarts, and
 * possibly sooner.  They are to be considered usable for one connection only,
 * although temporary caching may be used to improve efficiency.  In general,
 * do not rely on the same certificate to stay available.  Also, do not expect
 * public visibility of this identity in LDAP, DNS, or other identity showcase.
 *
 * Note that it should be assumed that these identities require special setup
 * in the remote node; if it is a full-blown TLS Pool, it will not appreciate
 * the locality of the identity, and demand more infrastructural confirmation
 * in identity showcases.  One example of its use however, is towards lame
 * and old-fashioned remote services and towards highly structured local users,
 * such as off-the-shelve browsers that require a HTTPS proxy.
 *
 * TODO: This is unimplemented behaviour; the flag is merely allocated.
 * For now, the response is the same as in lieu of configuration of a
 * root key and cert, namely to return DB_NOTFOUND.
 */
#define PIOF_LIDENTRY_ONTHEFLY			0x00200000

#ifdef __cplusplus
}
#endif

#endif //TLSPOOL_COMMANDS_H

