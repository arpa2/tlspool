/* tlspool/tlspool.h -- Structure definitions for the UNIX socket protocol */


#include <stdint.h>


#define TLSPOOL_IDENTITY_V1	"20130710tlspool@openfortress.nl"


/****************************** STRUCTURES *****************************/


/*
 * TLS pool communication proceeds over a UNIX file system socket, by
 * sending and receiving messages like below.
 *
 * The order of events is always one where the application connecting
 * to the socket sends messages, and the TLS pool always sends a reply.
 * Depending on the command, this reply may be fast or slow, but there
 * will always be a reply as long as the connection is kept open.  If
 * the application can handle concurrent communication, it may send
 * more than one packet at a time.  The reply will always copy the
 * pio_reqid field from the request to facilitate this; the application
 * should ensure different pio_reqid values for simultaneously sent
 * requests.
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
 * from the TLS pool.  The opposite does not hold, as there are secrets
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
	uint32_t pio_reqid;	// Request/Response identifier
	uint32_t pio_cmd;	// Command tag with semantic version
	union pio_data {
		struct {
			int errno;		// See <errno.h>
			char message [128];
		} piocmd_error;
		struct {
			char YYYYMMDD_producer [8+128];	// when & who?
		} piocmd_ping;
		struct {
			uint32_t flags;		// PIOF_xxx below
			uint32_t local;		// Locally defined bits
			uint8_t ipproto;	// IPPROTO_TCP, _UDP, _SCTP
			uint16_t streamid;	// Needed for SCTP
			char localid [128];	// Local ID or empty string
			char remoteid [128];	// Remote ID or empty string
		} piocmd_starttls;
	} pio_data;
};


/*
 * The tlspool_queueitem is a simple structure that supports storage of
 * the command packets in a bidirectionally linked queue.  This may be
 * of use for concurrent operations with the socket communication.
 */

struct tlspool_queueitem {
	struct poolio_q *pioq_next;	// Next queue item
	struct poolio_q *pioq_prev;	// Previous queue item
	struct poolio pioq_message;	// Transmitted message content
};


/******************************** COMMANDS *******************************/


/* An error packet is sent if the other party is unwilling to continue
 * the current exchange.  It explains why, through a code and message,
 * in the piocmd_error type.  Error codes are defined in <errno.h>
 */
#define PIOC_SUCCESS_V1			0x00000000


/* An error packet is sent if the other party is unwilling to continue
 * the current exchange.  It explains why, through a code and message,
 * in the piocmd_error type.  Error codes are defined in <errno.h>
 */
#define PIOC_ERROR_V1			0x00000001


/* A simple command to exchange courtesy, keepalives and potentially
 * identifying information of the peers.  The same packet is used in
 * both directions.
 * The string in piocmd_ping.YYYYMMDD_producer describes the sender's
 * semantics with an identity comprising of a YYYYMMDD timestamp for
 * the software semantics version, plus a domain or user@domain identity
 * representing the producer at that time, terminated with '\0'.
 */
#define PIOC_PING_V1			0x00000010


/* Start a TLS sequence as a TLS client.  This uses PIO_STARTTLS_xxx
 * flags, defined below.  The local definitions of the TLS pool define
 * part of the semantics.
 * The payload data is defined in piocmd_starttls and is the same
 * for the client and server, and for request and response.  Clients
 * usually know the remoteid, and should fill that field instead of
 * leaving it an empty string.  They may already present their localid
 * or leave it open for possible interaction during the TLS exchange.
 */
#define PIOC_STARTTLS_CLIENT_V1		0x00000020


/* Start a TLS sequence as a TLS server.  This uses PIO_STARTTLS_xxx
 * flags, defined below.  The local definitions of the TLS pool define
 * part of the semantics.
 * The payload data is defined in piocmd_starttls and is the same
 * for the client and server, and for request and response.  Servers
 * do not always know the remoteid, and may set this to an empty string
 * to skip checking it.  They may not even know their localid if they
 * service many, so it is even possible to set that to an empty string
 * and leave it to the TLS exchange to propose localid values.
 */
#define PIOC_STARTTLS_SERVER_V1		0x00000021


/* When a client initiates TLS, it may have started off with an empty
 * string as its localid.  When a server serves a multitude of domains,
 * it may have done the same.  This can lead to a response by the TLS
 * daemon, proposing a localid that can be modified by the application
 * and sent back in the same message format.  The remoteid is sent
 * by the TLS pool as extra information, but it is an empty string if
 * the information is unavailable.
 * Be prepared to receive zero or more of these proposals in the course
 * of a TLS exchange.  Especially when rejecting one localid there may
 * be ways for the TLS pool to propose other localid values.
 * The payload used is the pioc_starttls, but only the localid and
 * remoteid are meaningful when sent by the TLS pool, and only the
 * localid is interpreted when it returns to the TLS pool.
 */
#define PIOC_STARTTLS_LOCALID_V1	0x00000028


/* TODO: Define accounting as a best-effort, forked RADIUS interaction */

/* TODO: Possibly support renegotiation, like for explicit authn */


/* This command bit that marks a command as local.  Local commands are always
 * a bit of a risk, and should incorporate some way of identifying the
 * source of the command, or would otherwise be wise to exercise complete
 * control over the visibility of the extension code.  Picking rather
 * arbitrary codes may also help somewhat.
 */
#define PIOC_LOCAL			0x80000000


/********************************* FLAGS ********************************/


/* PIOF_STARTTLS_xxx flags are sent and received in piocmd_starttls.
 *
 * When sent to the TLS pool, they may provide it some freedom; when
 * it is still set in the response then this freedom has been exercised.
 *
 * Other flags indicate additional requirements.  When these are not met,
 * an error will be raised.  Their meaning in the response is meaningless.
 */


/* PIOF_STARTTLS_DTLS requests to setup DTLS instead of TLS.
 */
#define PIOF_STARTTLS_DTLS			0x00000001


/* PIOF_STARTTLS_REQUIRE_DNSSEC tells the TLS pool that DNSSEC must be
 * used for all information in DNS; so, a self-acclaimed I-can-do-without
 * domain is no longer permitted to connect over TLS.  The TLS pool may
 * rely on an external resolver to properly set the AD bits.
 */
#define PIOF_STARTTLS_REQUIRE_DNSSEC		0x00000010


/* PIOF_STARTTLS_TIGHTEN_LDAP tells the TLS pool that LDAP connections must
 * be secured through TLS.  In addition, the certificate used by LDAP will
 * be verified as is normally done for domain certificates.  Normally, that
 * means it must be acknowledged in a TLSA record.  Users and domains from
 * LDAP servers that do not live up to this are no longer trusted as peers
 * on grounds of their occurrence in LDAP alone.
 */
#define PIOF_STARTTLS_REQUIRE_LDAP_CERT		0x00000020
#define PIOF_STARTTLS_REQUIRE_LDAP_DANE		0x00000040
#define PIOF_STARTTLS_REQUIRE_LDAP_SECURITY	0x00000060


/* PIOF_STARTTLS_SKIP_EXT_AUTHN tells the TLS pool that no external
 * authentication is needed on top of the normal operations of the
 * TLS pool.  Usually, if an external authentication source is configured,
 * it will be RADIUS.  If it is not even configured, then this flag is of
 * no consequence.
 */
#define PIOF_STARTTLS_SKIP_EXT_AUTHN		0x00000080


/* PIOF_STARTTLS_SKIP_EXT_AUTHZ tells the TLS pool that no external
 * authorization is needed on top of the normal operations of the
 * TLS pool.  Usually, if an external authorization source is configured,
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


/* PIOF_STARTTLS_IGNORE_CACHES requires the TLS pool to perform the
 * validation here and now.  It will not accept cached results from
 * recent encounters as sufficient proof that the remote peer has
 * the acclaimed identity.  This can be used at places in an
 * interaction where the identity of the remote peer must be firmly
 * established.  Note that bypassing the caches dramatically increases
 * the amount of work for the TLS pool, and should thus be used with
 * care.  Note that the validation outcome may still be cached, for
 * future use when the peer relation is more relaxed.
 */
#define PIOF_STARTTLS_IGNORE_CACHES		0x00000400


/* PIOF_STARTTLS_REQUEST_REMOTEID means that the TLS pool should not
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


/* PIOF_STARTTLS_IGNORE_REMOTEID means that the TLS pool need not bother
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


