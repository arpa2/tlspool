/* tlspool/starttls.c -- Setup and validation handler for TLS session */

#include "whoami.h"

#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <memory.h>
#include <string.h>
#include <pthread.h>
#include <assert.h>

#include <ctype.h>

#include <unistd.h>
#include <syslog.h>
#include <errno.h>

#include <gnutls/gnutls.h>
#include <gnutls/pkcs11.h>
#include <gnutls/abstract.h>
#include <gnutls/dane.h>

#include <p11-kit/pkcs11.h>

#include <tlspool/commands.h>
#include <tlspool/internal.h>

#include <libtasn1.h>

#include <krb5.h>
/* Plus, from k5-int.h: */
krb5_error_code KRB5_CALLCONV krb5_decrypt_tkt_part(krb5_context,
                                                    const krb5_keyblock *,
                                                    krb5_ticket * );


#include <quick-der/api.h>
#include <quick-der/rfc4120.h>
typedef DER_OVLY_rfc4120_Ticket ticket_t;
typedef DER_OVLY_rfc4120_Authenticator authenticator_t;
typedef DER_OVLY_rfc4120_EncryptedData encrypted_data_t;

#include <tlspool/internal.h>

#ifdef WINDOWS_PORT
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <poll.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <krb5.h>

#ifndef __MINGW64__
#include <arpa/inet.h>
#endif
#include <netinet/in.h>
#endif

#ifdef WINDOWS_PORT
#include <windows.h>
#define RECV_FLAGS 0
#define SHUT_RD SD_RECEIVE
#define SHUT_WR SD_SEND
#else /* WINDOWS_PORT */
#define RECV_FLAGS MSG_DONTWAIT | MSG_NOSIGNAL
#endif /* WINDOWS_PORT */

#include "manage.h"
#include "donai.h"
#include "trust.h"


#if EXPECTED_LID_TYPE_COUNT != LID_TYPE_CNT
#error "Set EXPECTED_LID_TYPE_COUNT in <tlspool/internal.h> to match LID_TYPE_CNT"
#endif


/* This module hosts TLS handlers which treat an individual connection.
 *
 * Initially, the TLS setup is processed, which means validating the
 * connection.  If and when this succeeds, a continued process is needed
 * to encrypt and decrypt traffic while it is in transit.
 *
 * Every TLS connection (including the attempt to set it up) is hosted in
 * its own thread.  This means that it can abide time to wait for PINENTRY,
 * LOCALID or LIDENTRY responses.  It also means a very clear flow when the
 * time comes to destroy a connection.
 *
 * While encrypting and decrypting traffic passing through, the thread
 * will use its own poll() call, and thus offload the potentially large
 * one of the main thread, which is supposed to be a low-traffic task.
 * The set of file descriptors used by the session-handler threads are
 * in contrast very small and can easily be started for every single
 * packet passing through.
 *
 * Might the user terminate a process while this one is waiting for a
 * callback command request, then the main TLS pool thread will take
 * care of taking down this thread.  To that end, it sets the followup
 * pointer that normally holds a callback response to NULL, and then
 * permits this thread to run again.  This will lead to a shutdown of
 * this process, and proper closing of all connections.  The remote peer
 * will therefore see the result of a local kill as a connection reset.
 *
 * In case one of the end points of the connection is terminated, a
 * similar thing will happen; the thread will terminate itself after
 * a cleanup of any outstanding resources.  This, once again, leads
 * to passing on the reset of a connection between the encrypted and
 * side of the connection.
 */



/*
 * GnuTLS infrastructure setup.
 * Session-shared DH-keys, credentials structures, and so on.
 */
static gnutls_dh_params_t dh_params;

struct credinfo {
	gnutls_credentials_type_t credtp;
	void *cred;
};

#define EXPECTED_SRV_CREDCOUNT 3
#define EXPECTED_CLI_CREDCOUNT 3
static struct credinfo srv_creds [EXPECTED_SRV_CREDCOUNT];
static struct credinfo cli_creds [EXPECTED_CLI_CREDCOUNT];
static int srv_credcount = 0;
static int cli_credcount = 0;
static const char const *onthefly_p11uri = "pkcs11:manufacturer=ARPA2.net;token=TLS+Pool+internal;object=on-the-fly+signer;type=private;serial=1";
static unsigned long long onthefly_serial;  //TODO: Fill with now * 1000
static gnutls_x509_crt_t onthefly_issuercrt = NULL;
static gnutls_privkey_t onthefly_issuerkey = NULL;
static gnutls_x509_privkey_t onthefly_subjectkey = NULL;
static pthread_mutex_t onthefly_signer_lock = PTHREAD_MUTEX_INITIALIZER;

#ifdef HAVE_TLS_KDH
static krb5_context krbctx_cli, krbctx_srv;
static krb5_keytab  krb_kt_cli, krb_kt_srv;
static bool         got_cc_cli, got_cc_srv;
static int have_key_tgt_cc (
				struct command *cmd, // in, session context
				krb5_context ctx,    // in, kerberos context
				bool use_cc,         // in, whether to use cc
				krb5_kvno kvno,      // in, kvno (0 for highest)
				krb5_enctype enctype,// in, enctype (0 for any)
				char *p11uri,	     // in/opt, PKCS #11 pwd URI
				krb5_keytab kt,	     // in/opt, keytab
				krb5_keyblock *key,  // opt/opt session key
				krb5_creds **tgt,    // out/opt, tkt granting tkt
				krb5_ccache *cc);    // out/opt, cred cache
static int have_service_ticket (
				struct command *cmd, // in, session context
				krb5_context ctx,    // in, kerberos context
				krb5_ccache cc_opt,  // in/opt, credcache
				krb5_principal cli,  // in, client principal
				krb5_creds **ticket);// out/opt, tkt granting tkt
#endif


/* The local variation on the ctlkeynode structure, with TLS-specific fields
 */
struct ctlkeynode_tls {
	struct ctlkeynode regent;	// Structure for ctlkey_register()
	gnutls_session_t session;	// Additional data specifically for TLS
	pthread_t owner;		// For interruption of copycat()
	int plainfd;			// Plain-side connection
	int cryptfd;			// Crypt-side connection
};

/* A local structure used for iterating over PKCS #11 entries.  This is used
 * to iterate over password attempts, no more than MAX_P11ITER_ATTEMPTS though.
 *
 * When a password is requested but none is available, the password request
 * will be passed to the user using the PIN callback mechanism.  When this
 * is done, a warning may be given that the TLS Pool overtakes control over
 * the account (when thusly configured).  In support of that option, the
 * $attempt is counted and the respective $p11pwd is CK_INVALID_HANDLE.
 * TODO: Perhaps interact for saving, such as entering an certain string?
 *
 * When a number of attempts needs to be made before success, then any
 * objects that precede a succeeded $attempt can be removed.  The same may
 * be true for any objects after it.
 *
 * This mechanism is useful during password changes.  When a new password is
 * desired by the KDC, then a random object is created and returned twice.
 * To support repeated delivery, the password is stored in $newpwd;
 * In this case, the safest choice is still to leave the last $p11pwd.
 *
 * The caller may decide to invoke the password changing procedure, namely
 * after manual entry as evidenced by the condition
 *	(attempts >= 0) &&
 *	(attempts < MAX_P11_ITER_ATTEMPTS) &&
 *	(p11pwd [attempt] == CK_INVALID_HANDLE)
 *
 * TODO: This is a designed data structure, but not yet installed.
 *
 * TODO: It is more useful to abolish passwords, and truly use PKCS #11.
 */
#define MAX_P11ITER_ATTEMPTS 3
struct pkcs11iter {
	struct command *cmd;		// The session command structure
	CK_SESSION_HANDLE p11ses;	// The PKCS #11 session in motion
	int attempt;			// Starts at -1, incremented by pwd entry
	CK_OBJECT_HANDLE p11pwd [MAX_P11ITER_ATTEMPTS];
					// Sequence of $attempt objects returned
	CK_OBJECT_HANDLE newpwd;	// Set when a new password was offered
};

/* The list of accepted Exporter Label Prefixes for starttls_prng()
 */
char *tlsprng_label_prefixes [] = {
	// Forbidden by RFC 5705: "client finished",
	// Forbidden by RFC 5705: "server finished",
	// Forbidden by RFC 5705: "master secret",
	// Forbidden by RFC 5705: "key expansion",
	"client EAP encryption",		// not suited for DTLS
	"ttls keying material",			// not suited for DTLS
	"ttls challenge",			// not suited for DTLS
	"EXTRACTOR-dtls_srtp",
	"EXPORTER_DTLS_OVER_SCTP",
	"EXPORTER-ETSI-TC-M2M-Bootstrap",
	"EXPORTER-ETSI-TC-M2M-Connection",
	"TLS_MK_Extr",
	"EXPORTER_GBA_Digest",
	"EXPORTER: teap session key seed",	// not suited for DTLS
	"EXPORTER-oneM2M-Bootstrap",
	"EXPORTER-oneM2M-Connection",
	NULL
};

/* The registry with the service names that are deemed safe for an
 * anonymous precursor phase; that is, the service names that may offer
 * ANON-DH initially, and immediately renegotiate an authenticated
 * connection.  See doc/anonymising-precursor.* for more information.
 *
 * The registry is ordered by case-independent service name, so it can
 * be searched in 2log time.  Service names are as defined by IANA in the
 * "Service Name and Transport Protocol Port Number Registry".
 *
 * The entries in the registry depend on the role played; either as a
 * client or as a server.  This refers to the local node, and depends on
 * uncertainty of the remote party's TLS implementation and whether or
 * not the protocol could lead to the remote sending information that
 * requires authentication before the secure renogiation into an
 * authenticated connection has been completed by this side.  This is
 * a protocol-dependent matter and the registry provided here serves to
 * encapsulate this knowledge inside the TLS Pool instead of bothering
 * application designers with it.  Entries that are not found in the
 * registry are interpreted as not allowing an anonymising precursor.
 *
 * Note that ANONPRE_EXTEND_MASTER_SECRET cannot be verified before
 * GnuTLS version 3.4.0; see "imap" below for the resulting impact.  This
 * also impacts dynamic linking, because 3.4.0 introduces the new function
 * gnutls_ext_get_data() that is used for this requirement.
 */
#define ANONPRE_FORBID 0x00
#define ANONPRE_CLIENT 0x01
#define ANONPRE_SERVER 0x02
#define ANONPRE_EITHER (ANONPRE_CLIENT | ANONPRE_SERVER)
#define ANONPRE_EXTEND_MASTER_SECRET 0x10
struct anonpre_regentry {
	char *service;
	uint8_t flags;
};
struct anonpre_regentry anonpre_registry [] = {
/* This registry is commented out for now, although the code to use it seems
 * to work fine.  GnuTLS however, does not seem to support making the switch
 * from ANON-ECDH to an authenticated handshake.  Details:
 * http://lists.gnutls.org/pipermail/gnutls-help/2015-November/003998.html
 *
	{ "generic_anonpre", ANONPRE_EITHER },	// Name invalid as per RFC 6335
	{ "http", ANONPRE_CLIENT },	// Server also if it ignores client ID
#if GNUTLS_VERSION_NUMBER < 0x030400
	{ "imap", ANONPRE_SERVER },
#else
	{ "imap", ANONPRE_EITHER | ANONPRE_EXTEND_MASTER_SECRET },
#endif
	{ "pop3", ANONPRE_EITHER },
	{ "smtp", ANONPRE_EITHER },
 *
 * End of commenting out the registry
 */
};
const int anonpre_registry_size = sizeof (anonpre_registry) / sizeof (struct anonpre_regentry);


/* The registry of Key Usage and Extended Key Usage for any given service name.
 */
static const char *http_noncrit [] = { GNUTLS_KP_TLS_WWW_SERVER, GNUTLS_KP_TLS_WWW_CLIENT, NULL };
struct svcusage_regentry {
	char *service;
	unsigned int usage;
	const char **oids_non_critical;
	const char **oids_critical;
};
struct svcusage_regentry svcusage_registry [] = {
	{ "generic_anonpre",
		GNUTLS_KEY_KEY_ENCIPHERMENT |
		GNUTLS_KEY_KEY_AGREEMENT,
		NULL,
		NULL
	},
	{ "http",
		GNUTLS_KEY_DIGITAL_SIGNATURE |
		GNUTLS_KEY_KEY_ENCIPHERMENT |
		GNUTLS_KEY_KEY_AGREEMENT,
		http_noncrit,
		NULL
	},
};
const int svcusage_registry_size = sizeof (svcusage_registry) / sizeof (struct svcusage_regentry);


/* The maximum number of bytes that can be passed over a TLS connection before
 * the authentication is complete in case of a anonymous precursor within a
 * protocol that ensures that this cannot be a problem.
 */
int maxpreauth;

/* The priorities cache for "NORMAL" -- used to preconfigure the server,
 * actually to overcome its unwillingness to perform the handshake, and
 * leave it to srv_clienthello() to setup the priority string.
 */
gnutls_priority_t priority_normal;


/* Map a GnuTLS call (usually a function call) to a POSIX errno,
 * optionally reporting an errstr to avoid loosing information.
 * Retain errno if it already exists.
 * Continue if errno differs from 0, GnuTLS may "damage" it even when OK. */
#define E_g2e(errstr,gtlscall) { \
	if (gtls_errno == GNUTLS_E_SUCCESS) { \
		gtls_errno = (gtlscall); \
		if (gtls_errno != GNUTLS_E_SUCCESS) { \
			error_gnutls2posix (gtls_errno, errstr); \
		} \
	} \
}

/* Cleanup when GnuTLS leaves errno damaged but returns no gtls_errno */
#define E_gnutls_clear_errno() { \
	if (gtls_errno == GNUTLS_E_SUCCESS) { \
		errno = 0; \
	} \
}

/* Error number translation, including error string setup.  See E_g2e(). */
void error_gnutls2posix (int gtls_errno, char *new_errstr) {
	char *errstr;
	register int newerrno;
	//
	// Sanity checks
	if (gtls_errno == GNUTLS_E_SUCCESS) {
		return;
	}
	errstr =  error_getstring ();
	if (errstr != NULL) {
		return;
	}
	//
	// Report the textual error
	if (new_errstr == NULL) {
		new_errstr = "GnuTLS error";
	}
	tlog (TLOG_TLS, LOG_ERR, "%s: %s",
		new_errstr,
		gnutls_strerror (gtls_errno));
	error_setstring (new_errstr);
	//
	// Translate error to a POSIX errno value
	switch (gtls_errno) {
	case GNUTLS_E_SUCCESS:
		return;
	case GNUTLS_E_UNKNOWN_COMPRESSION_ALGORITHM:
	case GNUTLS_E_UNKNOWN_CIPHER_TYPE:
	case GNUTLS_E_UNSUPPORTED_VERSION_PACKET:
	case GNUTLS_E_UNWANTED_ALGORITHM:
	case GNUTLS_E_UNKNOWN_CIPHER_SUITE:
	case GNUTLS_E_UNSUPPORTED_CERTIFICATE_TYPE:
	case GNUTLS_E_X509_UNKNOWN_SAN:
	case GNUTLS_E_DH_PRIME_UNACCEPTABLE:
	case GNUTLS_E_UNKNOWN_PK_ALGORITHM:
	case GNUTLS_E_NO_TEMPORARY_RSA_PARAMS:
	case GNUTLS_E_NO_COMPRESSION_ALGORITHMS:
	case GNUTLS_E_NO_CIPHER_SUITES:
	case GNUTLS_E_OPENPGP_FINGERPRINT_UNSUPPORTED:
	case GNUTLS_E_X509_UNSUPPORTED_ATTRIBUTE:
	case GNUTLS_E_UNKNOWN_HASH_ALGORITHM:
	case GNUTLS_E_UNKNOWN_PKCS_CONTENT_TYPE:
	case GNUTLS_E_UNKNOWN_PKCS_BAG_TYPE:
	case GNUTLS_E_NO_TEMPORARY_DH_PARAMS:
	case GNUTLS_E_UNKNOWN_ALGORITHM:
	case GNUTLS_E_UNSUPPORTED_SIGNATURE_ALGORITHM:
	case GNUTLS_E_UNSAFE_RENEGOTIATION_DENIED:
	case GNUTLS_E_X509_UNSUPPORTED_OID:
	case GNUTLS_E_CHANNEL_BINDING_NOT_AVAILABLE:
	case GNUTLS_E_INCOMPAT_DSA_KEY_WITH_TLS_PROTOCOL:
	case GNUTLS_E_ECC_NO_SUPPORTED_CURVES:
	case GNUTLS_E_ECC_UNSUPPORTED_CURVE:
	case GNUTLS_E_X509_UNSUPPORTED_EXTENSION:
	case GNUTLS_E_NO_CERTIFICATE_STATUS:
	case GNUTLS_E_NO_APPLICATION_PROTOCOL:
#ifdef GNUTLS_E_NO_SELF_TEST
	case GNUTLS_E_NO_SELF_TEST:
#endif
		newerrno = EOPNOTSUPP;
		break;
	case GNUTLS_E_UNEXPECTED_PACKET_LENGTH:
	case GNUTLS_E_INVALID_REQUEST:
		newerrno = EINVAL;
		break;
	case GNUTLS_E_INVALID_SESSION:
	case GNUTLS_E_REHANDSHAKE:
	case GNUTLS_E_CERTIFICATE_KEY_MISMATCH:
		newerrno = ENOTCONN;
		break;
	case GNUTLS_E_PUSH_ERROR:
	case GNUTLS_E_PULL_ERROR:
	case GNUTLS_E_PREMATURE_TERMINATION:
	case GNUTLS_E_SESSION_EOF:
		newerrno = ECONNRESET;
		break;
	case GNUTLS_E_UNEXPECTED_PACKET:
	case GNUTLS_E_WARNING_ALERT_RECEIVED:
	case GNUTLS_E_FATAL_ALERT_RECEIVED:
	case GNUTLS_E_LARGE_PACKET:
	case GNUTLS_E_ERROR_IN_FINISHED_PACKET:
	case GNUTLS_E_UNEXPECTED_HANDSHAKE_PACKET:
	case GNUTLS_E_MPI_SCAN_FAILED:
	case GNUTLS_E_DECRYPTION_FAILED:
	case GNUTLS_E_DECOMPRESSION_FAILED:
	case GNUTLS_E_COMPRESSION_FAILED:
	case GNUTLS_E_BASE64_DECODING_ERROR:
	case GNUTLS_E_MPI_PRINT_FAILED:
	case GNUTLS_E_GOT_APPLICATION_DATA:
	case GNUTLS_E_RECORD_LIMIT_REACHED:
	case GNUTLS_E_ENCRYPTION_FAILED:
	case GNUTLS_E_PK_ENCRYPTION_FAILED:
	case GNUTLS_E_PK_DECRYPTION_FAILED:
	case GNUTLS_E_RECEIVED_ILLEGAL_PARAMETER:
	case GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE:
	case GNUTLS_E_PKCS1_WRONG_PAD:
	case GNUTLS_E_RECEIVED_ILLEGAL_EXTENSION:
	case GNUTLS_E_FILE_ERROR:
	case GNUTLS_E_ASN1_ELEMENT_NOT_FOUND:
	case GNUTLS_E_ASN1_IDENTIFIER_NOT_FOUND:
	case GNUTLS_E_ASN1_DER_ERROR:
	case GNUTLS_E_ASN1_VALUE_NOT_FOUND:
	case GNUTLS_E_ASN1_GENERIC_ERROR:
	case GNUTLS_E_ASN1_VALUE_NOT_VALID:
	case GNUTLS_E_ASN1_TAG_ERROR:
	case GNUTLS_E_ASN1_TAG_IMPLICIT:
	case GNUTLS_E_ASN1_TYPE_ANY_ERROR:
	case GNUTLS_E_ASN1_SYNTAX_ERROR:
	case GNUTLS_E_ASN1_DER_OVERFLOW:
	case GNUTLS_E_TOO_MANY_EMPTY_PACKETS:
	case GNUTLS_E_TOO_MANY_HANDSHAKE_PACKETS:
	case GNUTLS_E_SRP_PWD_PARSING_ERROR:
	case GNUTLS_E_BASE64_ENCODING_ERROR:
	case GNUTLS_E_OPENPGP_KEYRING_ERROR:
	case GNUTLS_E_BASE64_UNEXPECTED_HEADER_ERROR:
	case GNUTLS_E_OPENPGP_SUBKEY_ERROR:
	case GNUTLS_E_CRYPTO_ALREADY_REGISTERED:
	case GNUTLS_E_HANDSHAKE_TOO_LARGE:
	case GNUTLS_E_BAD_COOKIE:
	case GNUTLS_E_PARSING_ERROR:
	case GNUTLS_E_CERTIFICATE_LIST_UNSORTED:
	case GNUTLS_E_NO_PRIORITIES_WERE_SET:
#ifdef GNUTLS_E_PK_GENERATION_ERROR
	case GNUTLS_E_PK_GENERATION_ERROR:
#endif
#ifdef GNUTLS_E_SELF_TEST_ERROR
	case GNUTLS_E_SELF_TEST_ERROR:
#endif
#ifdef GNUTLS_E_SOCKETS_INIT_ERROR
	case GNUTLS_E_SOCKETS_INIT_ERROR:
#endif
		newerrno = EIO;
		break;
	case GNUTLS_E_MEMORY_ERROR:
	case GNUTLS_E_SHORT_MEMORY_BUFFER:
		newerrno = ENOMEM;
		break;
	case GNUTLS_E_AGAIN:
		newerrno = EAGAIN;
		break;
	case GNUTLS_E_EXPIRED:
	case GNUTLS_E_TIMEDOUT:
		newerrno = ETIMEDOUT;
		break;
	case GNUTLS_E_DB_ERROR:
#ifdef ENODATA
		newerrno = ENODATA;
#else
		newerrno = ENOENT;
#endif
		break;
	case GNUTLS_E_SRP_PWD_ERROR:
	case GNUTLS_E_INSUFFICIENT_CREDENTIALS:
	case GNUTLS_E_HASH_FAILED:
	case GNUTLS_E_PK_SIGN_FAILED:
	case GNUTLS_E_CERTIFICATE_ERROR:
	case GNUTLS_E_X509_UNSUPPORTED_CRITICAL_EXTENSION:
	case GNUTLS_E_KEY_USAGE_VIOLATION:
	case GNUTLS_E_NO_CERTIFICATE_FOUND:
	case GNUTLS_E_OPENPGP_UID_REVOKED:
	case GNUTLS_E_OPENPGP_GETKEY_FAILED:
	case GNUTLS_E_PK_SIG_VERIFY_FAILED:
	case GNUTLS_E_ILLEGAL_SRP_USERNAME:
	case GNUTLS_E_INVALID_PASSWORD:
	case GNUTLS_E_MAC_VERIFY_FAILED:
	case GNUTLS_E_IA_VERIFY_FAILED:
	case GNUTLS_E_UNKNOWN_SRP_USERNAME:
	case GNUTLS_E_OPENPGP_PREFERRED_KEY_ERROR:
	case GNUTLS_E_USER_ERROR:
	case GNUTLS_E_AUTH_ERROR:
		newerrno = EACCES;
		break;
	case GNUTLS_E_INTERRUPTED:
		newerrno = EINTR;
		break;
	case GNUTLS_E_INTERNAL_ERROR:
	case GNUTLS_E_CONSTRAINT_ERROR:
	case GNUTLS_E_ILLEGAL_PARAMETER:
		newerrno = EINVAL;
		break;
	case GNUTLS_E_SAFE_RENEGOTIATION_FAILED:
		newerrno = ECONNREFUSED;
		break;
	case GNUTLS_E_INCOMPATIBLE_GCRYPT_LIBRARY:
	case GNUTLS_E_INCOMPATIBLE_LIBTASN1_LIBRARY:
#ifdef GNUTLS_E_LIB_IN_ERROR_STATE
	case GNUTLS_E_LIB_IN_ERROR_STATE:
#endif
		newerrno = ENOEXEC;
		break;
	case GNUTLS_E_RANDOM_FAILED:
		newerrno = EBADF;
		break;
	case GNUTLS_E_CRYPTODEV_IOCTL_ERROR:
	case GNUTLS_E_CRYPTODEV_DEVICE_ERROR:
	case GNUTLS_E_HEARTBEAT_PONG_RECEIVED:
	case GNUTLS_E_HEARTBEAT_PING_RECEIVED:
	case GNUTLS_E_PKCS11_ERROR:
	case GNUTLS_E_PKCS11_LOAD_ERROR:
	case GNUTLS_E_PKCS11_PIN_ERROR:
	case GNUTLS_E_PKCS11_SLOT_ERROR:
	case GNUTLS_E_LOCKING_ERROR:
	case GNUTLS_E_PKCS11_ATTRIBUTE_ERROR:
	case GNUTLS_E_PKCS11_DEVICE_ERROR:
	case GNUTLS_E_PKCS11_DATA_ERROR:
	case GNUTLS_E_PKCS11_UNSUPPORTED_FEATURE_ERROR:
	case GNUTLS_E_PKCS11_KEY_ERROR:
	case GNUTLS_E_PKCS11_PIN_EXPIRED:
	case GNUTLS_E_PKCS11_PIN_LOCKED:
	case GNUTLS_E_PKCS11_SESSION_ERROR:
	case GNUTLS_E_PKCS11_SIGNATURE_ERROR:
	case GNUTLS_E_PKCS11_TOKEN_ERROR:
	case GNUTLS_E_PKCS11_USER_ERROR:
	case GNUTLS_E_CRYPTO_INIT_FAILED:
	case GNUTLS_E_PKCS11_REQUESTED_OBJECT_NOT_AVAILBLE:
	case GNUTLS_E_TPM_ERROR:
	case GNUTLS_E_TPM_KEY_PASSWORD_ERROR:
	case GNUTLS_E_TPM_SRK_PASSWORD_ERROR:
	case GNUTLS_E_TPM_SESSION_ERROR:
	case GNUTLS_E_TPM_KEY_NOT_FOUND:
	case GNUTLS_E_TPM_UNINITIALIZED:
	case GNUTLS_E_OCSP_RESPONSE_ERROR:
	case GNUTLS_E_RANDOM_DEVICE_ERROR:
#ifdef EREMOTEIO
		newerrno = EREMOTEIO;
#else
		newerrno = EIO;
#endif
		break;
	default:
		newerrno = EIO;
		break;
	}
	errno = newerrno;
	return;
}

/* Generate Diffie-Hellman parameters - for use with DHE
 * kx algorithms. TODO: These should be discarded and regenerated
 * once a day, once a week or once a month. Depending on the
 * security requirements.
 */
static gtls_error generate_dh_params (void) {
	unsigned int bits;
	int gtls_errno = GNUTLS_E_SUCCESS;
	bits = gnutls_sec_param_to_pk_bits (
		GNUTLS_PK_DH,
		GNUTLS_SEC_PARAM_LEGACY);
	//TODO// Acquire DH-params lock
	E_g2e ("Failed to initialise DH params",
		gnutls_dh_params_init (
			&dh_params));
	E_g2e ("Failed to generate DH params",
		gnutls_dh_params_generate2 (
			dh_params,
			bits));
	//TODO// Release DH-params lock
	return gtls_errno;
}

/* Load Diffie-Hellman parameters from file - or generate them when load fails.
 */
static gtls_error load_dh_params (void) {
	gnutls_dh_params_t dhp;
	gnutls_datum_t pkcs3;
	char *filename = cfg_tls_dhparamfile ();
	int gtls_errno = GNUTLS_E_SUCCESS;
	memset (&pkcs3, 0, sizeof (pkcs3));
	if (filename) {
		E_g2e ("No PKCS #3 PEM file with DH params",
			gnutls_load_file (
				filename,
				&pkcs3));
		E_gnutls_clear_errno ();
		E_g2e ("Failed to initialise DH params",
			gnutls_dh_params_init (
				&dhp));
		E_g2e ("Failed to import DH params from PKCS #3 PEM",
			gnutls_dh_params_import_pkcs3 (
				dhp,
				&pkcs3,
				GNUTLS_X509_FMT_PEM));
		E_gnutls_clear_errno ();
	}
	if (pkcs3.data != NULL) {
		free (pkcs3.data);
	}
	if (gtls_errno != GNUTLS_E_SUCCESS) {
		//
		// File failed to load, so try to generate fresh DH params
		int gtls_errno_stack0;
		gtls_errno = GNUTLS_E_SUCCESS;
		tlog (TLOG_CRYPTO, LOG_DEBUG, "Failed to load DH params from %s; generating fresh parameters", filename);
		E_g2e ("Failed to generate DH params",
			generate_dh_params ());
		gtls_errno_stack0 = gtls_errno;
		//TODO// Acquire DH-params lock
		E_g2e ("Failed to format DH params as PKCS #3 PEM",
			gnutls_dh_params_export2_pkcs3 (
				dh_params,
				GNUTLS_X509_FMT_PEM,
				&pkcs3));
		//TODO// Release DH-params lock
		if ((gtls_errno == GNUTLS_E_SUCCESS) && (filename != NULL)) {
			FILE *pemf;
			//
			// Best effor file save -- readback will parse
			pemf = fopen (filename, "w");
			if (pemf != NULL) {
				fwrite (pkcs3.data, 1, pkcs3.size, pemf);
				fclose (pemf);
				tlog (TLOG_FILES, LOG_DEBUG, "Saved DH params to %s (best-effort)", filename);
			}
			E_gnutls_clear_errno ();
		}
		gtls_errno = gtls_errno_stack0;
	} else {
		gnutls_dh_params_t old_dh;
		//TODO// Acquire DH-params lock
		old_dh = dh_params;
		dh_params = dhp;
		//TODO// Release DH-params lock
		if (old_dh) {
			gnutls_dh_params_deinit (old_dh);
		}
	}
	return gtls_errno;
}

/* Remove DH parameters, to be used during program cleanup. */
static void remove_dh_params (void) {
	if (dh_params) {
		gnutls_dh_params_deinit (dh_params);
		dh_params = NULL;
	}
}


/* A log printing function
 */
void log_gnutls (int level, const char *msg) {
	tlog (TLOG_TLS, level, "GnuTLS: %s", msg);
}


/* Implement the GnuTLS function for token insertion callback.  This function
 * refers back to the generic callback for token insertion.
 */
int gnutls_token_callback (void *const userdata,
				const char *const label,
				unsigned retry) {
	if (token_callback (label, retry)) {
		return GNUTLS_E_SUCCESS;
	} else {
		return GNUTLS_E_PKCS11_TOKEN_ERROR;
	}
}
 

/*
 * Implement the GnuTLS function for PIN callback.  This function calls
 * the generic PIN callback operation.
 */
int gnutls_pin_callback (void *userdata,
				int attempt,
				const char *token_url,
				const char *token_label,
				unsigned int flags,
				char *pin,
				size_t pin_max) {
	if (flags & GNUTLS_PIN_SO) {
		return GNUTLS_E_USER_ERROR;
	}
	if (pin_callback (attempt, token_url, NULL, pin, pin_max)) {
		return 0;
	} else {
		return GNUTLS_E_PKCS11_PIN_ERROR;
	}
}


/* Register a PKCS #11 provider with the GnuTLS environment. */
void starttls_pkcs11_provider (char *p11path) {
	unsigned int token_seq = 0;
	char *p11uri;
	if (gnutls_pkcs11_add_provider (p11path, NULL) != 0) {
		fprintf (stderr, "Failed to register PKCS #11 library %s with GnuTLS\n", p11path);
		exit (1);
	}
	while (gnutls_pkcs11_token_get_url (token_seq, 0, &p11uri) == 0) {
#ifdef DEBUG
		fprintf (stderr, "DEBUG: Found token URI %s\n", p11uri);
#endif
		//TODO// if (gnutls_pkcs11_token_get_info (p11uri, GNUTLS_PKCS11_TOKEN_LABEL-of-SERIAL-of-MANUFACTURER-of-MODEL, output, utput_size) == 0) { ... }
		gnutls_free (p11uri);
		token_seq++;
	}
	//TODO// Select token by name (value)
	//TODO// if PIN available then set it up
	//TODO:WHY?// free_p11pin ();
}

static void cleanup_starttls_credentials (void);/* Defined below */
static void cleanup_starttls_validation (void);	/* Defined below */
#ifdef HAVE_TLS_KDH
static void cleanup_starttls_kerberos (void);	/* Defined below */
static int setup_starttls_kerberos (void);	/* Defined below */
#endif
static int setup_starttls_credentials (void);	/* Defined below */

/* The global and static setup function for the starttls functions.
 */
void setup_starttls (void) {
	const char *curver;
	int gtls_errno = GNUTLS_E_SUCCESS;
	char *otfsigcrt, *otfsigkey;
	//
	// Setup configuration variables
	maxpreauth = cfg_tls_maxpreauth ();
	//
	// Basic library actions
	tlog (TLOG_TLS, LOG_DEBUG, "Compiled against GnuTLS version %s", GNUTLS_VERSION);
	curver = gnutls_check_version (GNUTLS_VERSION);
	tlog (TLOG_TLS, LOG_DEBUG, "Running against %s GnuTLS version %s", curver? "acceptable": "OLDER", curver? curver: gnutls_check_version (NULL));
	E_g2e ("GnuTLS global initialisation failed",
		gnutls_global_init ());
	E_gnutls_clear_errno ();
	E_g2e ("GnuTLS PKCS #11 initialisation failed",
		gnutls_pkcs11_init (
			GNUTLS_PKCS11_FLAG_MANUAL, NULL));
	//
	// Setup logging / debugging
	if (cfg_log_level () == LOG_DEBUG) {
		gnutls_global_set_log_function (log_gnutls);
		gnutls_global_set_log_level (9);
	}
	//
	// Setup Kerberos
#ifdef HAVE_TLS_KDH
	E_g2e ("Kerberos initialisation failed",
		setup_starttls_kerberos ());
#endif
	//
	// Setup callbacks for user communication
	gnutls_pkcs11_set_token_function (gnutls_token_callback, NULL);
	gnutls_pkcs11_set_pin_function (gnutls_pin_callback, NULL);
	//
	// Setup DH parameters
	E_g2e ("Loading DH params failed",
		load_dh_params ());
	//
	// Setup shared credentials for all client server processes
	E_g2e ("Failed to setup GnuTLS callback credentials",
		setup_starttls_credentials ());
	//
	// Parse the default priority string
#ifdef HAVE_TLS_KDH
	E_g2e ("Failed to setup NORMAL priority cache",
		gnutls_priority_init (&priority_normal,
			"NONE:"
			"%ASYM_CERT_TYPES:"
			"+VERS-TLS-ALL:+VERS-DTLS-ALL:"
			"+COMP-NULL:"
			"+CIPHER-ALL:+CURVE-ALL:+SIGN-ALL:+MAC-ALL:"
			"+ANON-ECDH:"
			"+ECDHE-KRB:" // +ECDHE-KRB-RSA:+ECDHE-KRB-ECDSA:"
			"+ECDHE-RSA:+DHE-RSA:+ECDHE-ECDSA:+DHE-DSS:+RSA:"
			"+CTYPE-SRV-KRB:+CTYPE-SRV-X.509:+CTYPE-SRV-OPENPGP:"
			"+CTYPE-CLI-KRB:+CTYPE-CLI-X.509:+CTYPE-CLI-OPENPGP:"
			"+SRP:+SRP-RSA:+SRP-DSS",
			NULL));
#else
	E_g2e ("Failed to setup NORMAL priority cache",
		gnutls_priority_init (&priority_normal,
			"NONE:"
			"+VERS-TLS-ALL:+VERS-DTLS-ALL:"
			"+COMP-NULL:+CIPHER-ALL:+CURVE-ALL:+SIGN-ALL:+MAC-ALL:"
			"+ANON-ECDH:"
			"+ECDHE-RSA:+DHE-RSA:+ECDHE-ECDSA:+DHE-DSS:+RSA:"
			"+CTYPE-X.509:+CTYPE-OPENPGP:"
			"+SRP:+SRP-RSA:+SRP-DSS",
			NULL));
#endif
	//
	// Try to setup on-the-fly signing key / certificate and gen a certkey
	otfsigcrt = cfg_tls_onthefly_signcert ();
	otfsigkey = cfg_tls_onthefly_signkey ();
fprintf (stderr, "DEBUG: gtls_errno = %d, otfsigcrt == %s, otfsigkey == %s\n", gtls_errno, otfsigcrt? otfsigcrt: "NULL", otfsigkey? otfsigkey: "NULL");
	if ((gtls_errno == GNUTLS_E_SUCCESS) && (otfsigcrt != NULL)) {
		FILE *crtfile = NULL;
fprintf (stderr, "DEBUG: gtls_errno==%d when initialising onthefly_issuercrt\n", gtls_errno);
		E_g2e ("Failed to initialise on-the-fly issuer certificate structure",
			gnutls_x509_crt_init (&onthefly_issuercrt));
		if (strncmp (otfsigcrt, "file:", 5) == 0) {
			// Provisionary support for the "file:" prefix
			otfsigcrt += 5;
		}
		crtfile = fopen (otfsigcrt, "r");
		if (crtfile == NULL) {
			E_g2e ("Failed to open on-the-fly issuer certificate file",
				GNUTLS_E_FILE_ERROR);
fprintf (stderr, "DEBUG: gtls_errno==%d after failing to open file for onthefly_issuercrt\n", gtls_errno);
		} else {
			char crt [5001];
			size_t len = fread (crt, 1, sizeof (crt), crtfile);
			if (ferror (crtfile)) {
				E_g2e ("Failed to read on-the-fly issuer certificate from file",
					GNUTLS_E_FILE_ERROR);
			} else if ((len >= sizeof (crt)) || !feof (crtfile)) {
				E_g2e ("Unexpectedly long on-the-fly issuer certificate file",
					GNUTLS_E_FILE_ERROR);
			} else {
				gnutls_datum_t cd = {
					.data = crt,
					.size = len
				};
fprintf (stderr, "DEBUG: gtls_errno==%d before importing onthefly_issuercrt\n", gtls_errno);
				E_g2e ("Failed to import on-the-fly certificate from file",
					gnutls_x509_crt_import (onthefly_issuercrt, &cd, GNUTLS_X509_FMT_DER));
fprintf (stderr, "DEBUG: gtls_errno==%d after  importing onthefly_issuercrt\n", gtls_errno);
			}
			fclose (crtfile);
		}
	}
	if ((gtls_errno == GNUTLS_E_SUCCESS) && (otfsigkey != NULL)) {
		E_g2e ("Failed to initialise on-the-fly issuer private key structure",
			gnutls_privkey_init (&onthefly_issuerkey));
fprintf (stderr, "DEBUG: before onthefly p11 import, gtlserrno = %d\n", gtls_errno);
		E_g2e ("Failed to import pkcs11: URI into on-the-fly issuer private key",
			gnutls_privkey_import_pkcs11_url (onthefly_issuerkey, otfsigkey));
fprintf (stderr, "DEBUG: after  onthefly p11 import, gtlserrno = %d\n", gtls_errno);
	}
fprintf (stderr, "DEBUG: When it matters, gtls_errno = %d, onthefly_issuercrt %s NULL, onthefly_issuerkey %s NULL\n", gtls_errno, onthefly_issuercrt?"!=":"==", onthefly_issuerkey?"!=":"==");
	if ((gtls_errno == GNUTLS_E_SUCCESS) && (onthefly_issuercrt != NULL) && (onthefly_issuerkey != NULL)) {
		E_g2e ("Failed to initialise on-the-fly certificate session key",
			gnutls_x509_privkey_init (&onthefly_subjectkey));
		E_g2e ("Failed to generate on-the-fly certificate session key",
			gnutls_x509_privkey_generate (onthefly_subjectkey, GNUTLS_PK_RSA, 2048 /*TODO:FIXED*/, 0));
		if (gtls_errno == GNUTLS_E_SUCCESS) {
			tlog (TLOG_TLS, LOG_INFO, "Setup for on-the-fly signing with the TLS Pool");
		} else {
			tlog (TLOG_TLS, LOG_ERR, "Failed to setup on-the-fly signing (shall continue without it)");
			gnutls_x509_privkey_deinit (onthefly_subjectkey);
			onthefly_subjectkey = NULL;
		}
	} else {
		gtls_errno = GNUTLS_E_SUCCESS;
		E_gnutls_clear_errno ();
	}
	if (onthefly_subjectkey == NULL) {
		if (onthefly_issuercrt != NULL) {
			gnutls_x509_crt_deinit (onthefly_issuercrt);
			onthefly_issuercrt = NULL;
		}
		if (onthefly_issuerkey != NULL) {
			gnutls_privkey_deinit (onthefly_issuerkey);
			onthefly_issuerkey = NULL;
		}
	}
	//
	// Finally, check whether there was any error setting up GnuTLS
	if (gtls_errno != GNUTLS_E_SUCCESS) {
		tlog (TLOG_TLS, LOG_CRIT, "FATAL: GnuTLS setup failed: %s", gnutls_strerror (gtls_errno));
		exit (1);
	}
	//MOVED// //
	//MOVED// // Setup the management databases
	//MOVED// tlog (TLOG_DB, LOG_DEBUG, "Setting up management databases");
	//MOVED// E_e2e ("Failed to setup management databases",
	//MOVED// 	setup_management ());
	//MOVED// if (errno != 0) {
	//MOVED// 	tlog (TLOG_DB, LOG_CRIT, "FATAL: Management databases setup failed: %s", strerror (errno));
	//MOVED// 	exit (1);
	//MOVED// }
}

/* Cleanup the structures and resources that were setup for handling TLS.
 */
void cleanup_starttls (void) {
	//MOVED// cleanup_management ();
	if (onthefly_subjectkey != NULL) {
		gnutls_x509_privkey_deinit (onthefly_subjectkey);
		onthefly_subjectkey = NULL;
	}
	if (onthefly_issuercrt != NULL) {
		gnutls_x509_crt_deinit (onthefly_issuercrt);
		onthefly_issuercrt = NULL;
	}
	if (onthefly_issuerkey != NULL) {
		gnutls_privkey_deinit (onthefly_issuerkey);
		onthefly_issuerkey = NULL;
	}

	cleanup_starttls_credentials ();
#ifdef HAVE_TLS_KDH
	cleanup_starttls_kerberos ();
#endif
	remove_dh_params ();
	gnutls_pkcs11_set_pin_function (NULL, NULL);
	gnutls_pkcs11_set_token_function (NULL, NULL);
	gnutls_pkcs11_deinit ();
	gnutls_priority_deinit (priority_normal);
	gnutls_global_deinit ();
}


/*
 * The copycat function is a bidirectional transport between the given
 * remote and local sockets, but it will encrypt traffic from local to
 * remote, and decrypt traffic from remote to local.  It will do this
 * until one of the end points is shut down, at which time it will
 * return and assume the context will close down both pre-existing
 * sockets.
 *
 * This copycat actually has a few sharp claws to watch for -- shutdown
 * of sockets may drop the last bit of information sent.  First, the
 * signal POLLHUP is best ignored because it travels asynchronously.
 * Second, reading 0 is a good indicator of end-of-file and may be
 * followed by an shutdown of reading from that stream.  But, more
 * importantly, the other side must have this information forwarded
 * so it can shutdown.  This means that a shutdown for writing to that
 * stream is to be sent.  Even when *both* sides have agreed to not send
 * anything, they may still not have received all they were offered for
 * reading, so we should SO_LINGER on the sockets so they can acknowledge,
 * and after a timeout we can establish that shutdown failed and log and
 * return an error for it.
 * Will you believe that I had looked up if close() would suffice?  The man
 * page clearly stated yes.  However, these articles offer much more detail:
 * http://blog.netherlabs.nl/articles/2009/01/18/the-ultimate-so_linger-page-or-why-is-my-tcp-not-reliable
 * http://www.greenend.org.uk/rjk/tech/poll.html
 *
 * This function blocks during its call to poll(), in a state that can easily
 * be restarted.  This is when thread cancellation is temporarily enabled.
 * Other threads may use this to cancel the thread and have it joined with that
 * thread which will subsume its tasks and restart the handshake.  We might
 * later make this more advanced, by using a cancel stack push/pull mechanisms
 * to ensure that recv() always results in send() in spite of cancellation.
 *
 * The return value of copycat is a GNUTLS_E_ code, usually GNUTLS_E_SUCCESS.
 * For the moment, only one special value is of concern, namely
 * GNUTLS_E_REHANDSHAKE which client or server side may receive when an
 * attempt is made to renegotiate the security of the connection.
 */
static int copycat (int local, int remote, gnutls_session_t wrapped, pool_handle_t client) {
	char buf [1024];
	struct pollfd inout [3];
	ssize_t sz;
	struct linger linger = { 1, 10 };
	int have_client;
	int retval = GNUTLS_E_SUCCESS;

client = INVALID_POOL_HANDLE;
	inout [0].fd = local;
	inout [1].fd = remote;
#ifdef WINDOWS_PORT
	have_client = 0;
#else
	inout [2].fd = client;
	have_client = inout [2].fd != INVALID_POOL_HANDLE;
#endif
	if (!have_client) {
		inout [2].revents = 0;	// Will not be written by poll
		//FORK!=DETACH// inout [2].fd = ctlkey_signalling_fd;
	}
	inout [0].events = POLLIN;
	inout [1].events = POLLIN;
	inout [2].events = 0;	// error events only
	tlog (TLOG_COPYCAT, LOG_DEBUG, "Starting copycat cycle for local=%d, remote=%d, control=%d", local, remote, client);
	while (((inout [0].events | inout [1].events) & POLLIN) != 0) {
		int polled;
		assert (pthread_setcancelstate (PTHREAD_CANCEL_ENABLE,  NULL) == 0);
		pthread_testcancel ();	// Efficiency & Certainty
		polled = poll (inout, have_client? 3: 2, -1);
		assert (pthread_setcancelstate (PTHREAD_CANCEL_DISABLE, NULL) == 0);
		if (polled == -1) {
			tlog (TLOG_COPYCAT, LOG_DEBUG, "Copycat polling returned an error");
			break;	// Polling sees an error
		}
		if (inout [0].revents & POLLIN) {
			// Read local and encrypt to remote
			sz = recv (local, buf, sizeof (buf), RECV_FLAGS);
			tlog (TLOG_COPYCAT, LOG_DEBUG, "Copycat received %d local bytes (or error<0) from %d", (int) sz, local);
			if (sz == -1) {
				tlog (TLOG_COPYCAT, LOG_ERR, "Error while receiving: %s", strerror (errno));
				break;	// stream error
			} else if (sz == 0) {
				inout [0].events &= ~POLLIN;
				shutdown (local, SHUT_RD);
#ifdef WINDOWS_PORT
				setsockopt (remote, SOL_SOCKET, SO_LINGER, (const char *) &linger, sizeof (linger));
#else /* WINDOWS_PORT */
				setsockopt (remote, SOL_SOCKET, SO_LINGER, &linger, sizeof (linger));
#endif /* WINDOWS_PORT */
				gnutls_bye (wrapped, GNUTLS_SHUT_WR);
			} else if (gnutls_record_send (wrapped, buf, sz) != sz) {
				tlog (TLOG_COPYCAT, LOG_ERR, "gnutls_record_send() failed to pass on the requested bytes");
				break;	// communication error
			} else {
				tlog (TLOG_COPYCAT, LOG_DEBUG, "Copycat sent %d bytes to remote %d", (int) sz, remote);
			}
		}
		if (inout [1].revents & POLLIN) {
			// Read remote and decrypt to local
			sz = gnutls_record_recv (wrapped, buf, sizeof (buf));
			tlog (TLOG_COPYCAT, LOG_DEBUG, "Copycat received %d remote bytes from %d (or error if <0)", (int) sz, remote);
			if (sz < 0) {
				//TODO// Process GNUTLS_E_REHANDSHAKE
				if (sz == GNUTLS_E_REHANDSHAKE) {
					tlog (TLOG_TLS, LOG_INFO, "Received renegotiation request over TLS handle %d", remote);
					retval = GNUTLS_E_REHANDSHAKE;
					break;
				} else if (gnutls_error_is_fatal (sz)) {
					tlog (TLOG_TLS, LOG_ERR, "GnuTLS fatal error: %s", gnutls_strerror (sz));
					break;	// stream error
				} else {
					tlog (TLOG_TLS, LOG_INFO, "GnuTLS recoverable error: %s", gnutls_strerror (sz));
				}
			} else if (sz == 0) {
				inout [1].events &= ~POLLIN;
				shutdown (remote, SHUT_RD);
#ifdef WINDOWS_PORT
				setsockopt (local, SOL_SOCKET, SO_LINGER, (const char *) &linger, sizeof (linger));
#else /* WINDOWS_PORT */
				setsockopt (local, SOL_SOCKET, SO_LINGER, &linger, sizeof (linger));
#endif /* WINDOWS_PORT */
				shutdown (local, SHUT_WR);
			} else if (send (local, buf, sz, RECV_FLAGS) != sz) {
				break;	// communication error
			} else {
				tlog (TLOG_COPYCAT, LOG_DEBUG, "Copycat sent %d bytes to local %d", (int) sz, local);
			}
		}
		inout [0].revents &= ~(POLLIN | POLLHUP); // Thy copying cat?
		inout [1].revents &= ~(POLLIN | POLLHUP); // Retract thee claws!
		if ((inout [0].revents | inout [1].revents) & ~POLLIN) {
			tlog (TLOG_COPYCAT, LOG_DEBUG, "Copycat data connection polling returned a special condition");
			break;	// Apparently, one of POLLERR, POLLHUP, POLLNVAL
		}
#ifndef WINDOWS_PORT
		if (inout [2].revents & ~POLLIN) {
			if (have_client) {
				// This case is currently not ever triggered
				tlog (TLOG_COPYCAT, LOG_DEBUG, "Copycat control connection polling returned a special condition");
				break;	// Apparently, one of POLLERR, POLLHUP, POLLNVAL
			} else {
				inout [2].fd = client;
				have_client = inout [2].fd >= 0;
				if (have_client) {
					tlog (TLOG_COPYCAT, LOG_DEBUG, "Copycat signalling_fd polling raised a signal to set control fd to %d", inout [2].fd);
				} else {
					tlog (TLOG_COPYCAT, LOG_DEBUG, "Copycat signalling_fd polling raised a signal that could be ignored");
				}
				continue;
			}
		}
#endif /* !WINDOWS_PORT */
	}
	tlog (TLOG_COPYCAT, LOG_DEBUG, "Ending copycat cycle for local=%d, remote=%d", local, remote);
	return retval;
}


/* The callback function that retrieves certification information from either
 * the client or the server in the course of the handshake procedure.
 */
gtls_error clisrv_cert_retrieve (gnutls_session_t session,
				const gnutls_datum_t* req_ca_dn,
				int nreqs,
				const gnutls_pk_algorithm_t* pk_algos,
				int pk_algos_length,
				gnutls_pcert_st** pcert,
				unsigned int *pcert_length,
				gnutls_privkey_t *pkey) {
	gnutls_certificate_type_t certtp;
	gnutls_pcert_st *pc = NULL;
	struct command *cmd;
	char *lid, *rid;
	gnutls_datum_t privdatum = { NULL, 0 };
	gnutls_datum_t certdatum = { NULL, 0 };
	gnutls_openpgp_crt_t pgpcert = NULL;
	gnutls_openpgp_privkey_t pgppriv = NULL;
	int gtls_errno = GNUTLS_E_SUCCESS;
	int lidtype;
	int lidrole = 0;
	char *rolestr;
	char sni [sizeof (cmd->cmd.pio_data.pioc_starttls.localid)];
	size_t snilen = sizeof (sni);
	int snitype;
	int ok;
	uint32_t flags;
	char *p11priv;
	uint8_t *pubdata;
	int pubdatalen;
	gtls_error fetch_local_credentials (struct command *cmd);
	gnutls_pcert_st *load_certificate_chain (uint32_t flags, unsigned int *chainlen, gnutls_datum_t *certdatum);

	//
	// Setup a number of common references and structures
	errno = 0;
	*pcert = NULL;
	cmd = (struct command *) gnutls_session_get_ptr (session);
	if (cmd == NULL) {
		E_g2e ("No data pointer with session",
			GNUTLS_E_INVALID_SESSION);
		return gtls_errno;
	}
	if (cmd->cmd.pio_data.pioc_starttls.flags & PIOF_STARTTLS_LOCALROLE_CLIENT) {
		lidrole = LID_ROLE_CLIENT;
		rolestr = "client";
	} else if (cmd->cmd.pio_data.pioc_starttls.flags & PIOF_STARTTLS_LOCALROLE_SERVER) {
		lidrole = LID_ROLE_SERVER;
		rolestr = "server";
	} else {
		E_g2e ("TLS Pool command supports neither local client nor local server role",
			GNUTLS_E_INVALID_SESSION);
		return gtls_errno;
	}
	lid = cmd->cmd.pio_data.pioc_starttls.localid;
	rid = cmd->cmd.pio_data.pioc_starttls.remoteid;

	//
	// On a server, lookup the server name and match it against lid.
	// TODO: For now assume a single server name in SNI (as that is normal).
	if (lidrole == LID_ROLE_SERVER) {
		if (gnutls_server_name_get (session, sni, &snilen, &snitype, 0) || (snitype != GNUTLS_NAME_DNS)) {
			E_g2e ("Requested SNI error or not a DNS name",
				GNUTLS_E_NO_CERTIFICATE_FOUND);
			return gtls_errno;
		}
		if (*lid != '\0') {
			int atidx;
			for (atidx=128; atidx > 0; atidx--) {
				if (lid [atidx-1] == '@') {
					break;
				}
			}
			if (strncmp (sni, lid + atidx, sizeof (sni)-atidx) != 0) {
				tlog (TLOG_TLS, LOG_ERR, "SNI %s does not match preset local identity %s", sni, lid);
				E_g2e ("Requested SNI does not match local identity",
					GNUTLS_E_NO_CERTIFICATE_FOUND);
				return gtls_errno;
			}
		} else {
			// TODO: Should ask for permission before accepting SNI
			memcpy (lid, sni, sizeof (sni));
		}
	}

	//
	// Setup the lidtype parameter for responding
#ifdef HAVE_TLS_KDH
	certtp = gnutls_certificate_type_get_ours (session);
#else
	certtp = gnutls_certificate_type_get (session);
#endif
	if (certtp == GNUTLS_CRT_OPENPGP) {
		tlog (TLOG_TLS, LOG_INFO, "Serving OpenPGP certificate request as a %s", rolestr);
		lidtype = LID_TYPE_PGP;
	} else if (certtp == GNUTLS_CRT_X509) {
		tlog (TLOG_TLS, LOG_INFO, "Serving X.509 certificate request as a %s", rolestr);
		lidtype = LID_TYPE_X509;
#ifdef HAVE_TLS_KDH
	} else if (certtp == GNUTLS_CRT_KRB) {
		tlog (TLOG_TLS, LOG_INFO, "Serving Kerberos Ticket request as a %s", rolestr);
		lidtype = LID_TYPE_KRB5;
#endif
	} else {
		// GNUTLS_CRT_RAW, GNUTLS_CRT_UNKNOWN, or other
		tlog (TLOG_TLS, LOG_ERR, "Funny sort of certificate %d retrieval attempted as a %s", certtp, rolestr);
		E_g2e ("Requested certtype is neither X.509 nor OpenPGP",
			GNUTLS_E_CERTIFICATE_ERROR);
		return gtls_errno;
	}

	//
	// Find the prefetched local identity to use towards this remote
	// Send a callback to the user if none is available and accessible
	if (cmd->cmd.pio_data.pioc_starttls.flags & PIOF_STARTTLS_LOCALID_CHECK) {
		uint32_t oldcmd = cmd->cmd.pio_cmd;
		struct command *resp;
		cmd->cmd.pio_cmd = PIOC_STARTTLS_LOCALID_V2;
		tlog (TLOG_UNIXSOCK, LOG_DEBUG, "Calling send_callback_and_await_response with PIOC_STARTTLS_LOCALID_V2");
		resp = send_callback_and_await_response (cmd, 0);
		assert (resp != NULL);	// No timeout, should be non-NULL
		if (resp->cmd.pio_cmd != PIOC_STARTTLS_LOCALID_V2) {
			tlog (TLOG_UNIXSOCK, LOG_ERR, "Callback response has unexpected command code");
			cmd->cmd.pio_cmd = oldcmd;
			return GNUTLS_E_CERTIFICATE_ERROR;
		}
		assert (resp == cmd);  // No ERROR, so should be the same
		tlog (TLOG_UNIXSOCK, LOG_DEBUG, "Processing callback response that sets plainfd:=%d and lid:=\"%s\" for rid==\"%s\"", cmd->passfd, lid, rid);
		cmd->cmd.pio_cmd = oldcmd;
		//
		// Check that new rid is a generalisation of original rid
		// Note: This is only of interest for client operation
		if (lidrole == LID_ROLE_CLIENT) {
			selector_t newrid = donai_from_stable_string (rid, strlen (rid));
			donai_t oldrid = donai_from_stable_string (cmd->orig_starttls->remoteid, strlen (cmd->orig_starttls->remoteid));
			if (!donai_matches_selector (&oldrid, &newrid)) {
				return GNUTLS_E_NO_CERTIFICATE_FOUND;
			}
		}
		//
		// Now reiterate to lookup lid credentials in db_localid
		E_g2e ("Missing local credentials",
			fetch_local_credentials (cmd));
	}
	if (cmd->lids [lidtype - LID_TYPE_MIN].data == NULL) {
fprintf (stderr, "DEBUG: Missing certificate for local ID %s and remote ID %s\n", lid, rid);
		E_g2e ("Missing certificate for local ID",
			GNUTLS_E_NO_CERTIFICATE_FOUND);
		return gtls_errno;
	}

	//
	// Split the credential into its various aspects
	ok = dbcred_interpret (
		&cmd->lids [lidtype - LID_TYPE_MIN],
		&flags,
		&p11priv,
		&certdatum.data,
		&certdatum.size);
	tlog (TLOG_DB, LOG_DEBUG, "BDB entry has flags=0x%08x, p11priv=\"%s\", cert.size=%d", flags, p11priv, certdatum.size);
	//TODO// ok = ok && verify_cert_... (...); -- keyidlookup
	if (!ok) {
		gtls_errno = GNUTLS_E_CERTIFICATE_ERROR;
	}

	//
	// Allocate response structures
	*pcert_length = 0;
	*pcert = load_certificate_chain (flags, pcert_length, &certdatum);
	if (*pcert == NULL) {
		E_g2e ("Failed to load certificate chain",
			GNUTLS_E_CERTIFICATE_ERROR);
		return gtls_errno;
	}
	cmd->session_certificate = (intptr_t) (void *) *pcert;	//TODO// Used for session cleanup

	//
	// Setup private key
	E_g2e ("Failed to initialise private key",
		gnutls_privkey_init (
			pkey));
	if ((onthefly_subjectkey != NULL) && (strcmp (p11priv, onthefly_p11uri) == 0)) {
		// Setup the on-the-fly certification key as private key
		E_g2e ("Failed to import on-the-fly subject private key",
			gnutls_privkey_import_x509 (
				*pkey,
				onthefly_subjectkey,
				GNUTLS_PRIVKEY_IMPORT_COPY));
#ifdef HAVE_TLS_KDH
	} else if (lidtype == LID_TYPE_KRB5) {
		// Fake a private key for Kerberos (we sign it out here, not GnuTLS)
		E_g2e ("Failed to generate a private-key placeholder for Kerberos",
			gnutls_privkey_generate_krb (
				*pkey,
				0));
#endif
	} else {
		// Import the PKCS #11 key as the private key for use by GnuTLS
		if (gtls_errno == GNUTLS_E_SUCCESS) {
			cmd->session_privatekey = (intptr_t) (void *) *pkey;	//TODO// Used for session cleanup
		}
		E_g2e ("Failed to import PKCS #11 private key URI",
			gnutls_privkey_import_pkcs11_url (
				*pkey,
				p11priv));
	}
	E_gnutls_clear_errno ();

//TODO// Moved out (start)

	//
	// Setup public key certificate
	switch (lidtype) {
	case LID_TYPE_X509:
		E_g2e ("MOVED: Failed to import X.509 certificate into chain",
			gnutls_pcert_import_x509_raw (
				*pcert,
				&certdatum,
				GNUTLS_X509_FMT_DER,
				0));
		break;
	case LID_TYPE_PGP:
		E_g2e ("MOVED: Failed to import OpenPGP public key",
			gnutls_pcert_import_openpgp_raw (
				*pcert,
				&certdatum,
				GNUTLS_OPENPGP_FMT_RAW,
				NULL,	/* use master key */
				0));
		break;
#ifdef HAVE_TLS_KDH
	case LID_TYPE_KRB5:
		if (lidrole == LID_ROLE_CLIENT) {
			//
			// KDH-Only or KDH-Enhanced; fetch ticket for localid
			// and a TGT based on it for service/remoteid@REALM
			//
			// First, try to obtain a TGT and key, in various ways
			krb5_keyblock key;
			krb5_creds *tgt = NULL;
			krb5_creds *ticket = NULL;
			krb5_ccache cc = NULL;
			int status = 0;
			memset (&key,    0, sizeof (key   ));
			status = have_key_tgt_cc (
				cmd, krbctx_cli,
				1, 0, 0,
				p11priv,
				krb_kt_cli,
				&key, &tgt, &cc);
			if (status >= 1) {
				// We never use this key ourselves
				krb5_free_keyblock_contents (krbctx_cli, &key);
			}
			if (status < 2) {
				// Stop processing when no tgt was found
				gtls_errno = GNUTLS_E_NO_CERTIFICATE_FOUND;
				break;
			}
			//
			// Store client identity in session object
			if (0 != krb5_copy_principal (
					krbctx_cli,
					tgt->client,
					&cmd->krbid_cli)) {
				krb5_free_creds (krbctx_cli, tgt);
				tgt = NULL;
				if (cc != NULL) {
					krb5_cc_close (krbctx_cli, cc);
					cc = NULL;
				}
				gtls_errno = GNUTLS_E_NO_CERTIFICATE_FOUND;
				break;
			}
			//
			// Now find a service ticket to talk to, and its key
			//TODO// Pass credcache instead?
			status = have_service_ticket (
				cmd, krbctx_cli,
				cc,
				cmd->krbid_cli,
				&ticket);
			if (cc != NULL) {
				// We don't need cc anymore below
				krb5_cc_close (krbctx_cli, cc);
			}
			if (status < 1) {
				// Stop processing when no ticket was found
				krb5_free_creds (krbctx_cli, tgt);
				tgt = NULL;
				gtls_errno = GNUTLS_E_NO_CERTIFICATE_FOUND;
				break;
			}
			//
			// Only for KDH-Only mode can the client rely on a
			// server principal taken from the ticket;
			// So only store krbid_srv for KDH-Only mode.
			if ((gnutls_certificate_type_get_peers (cmd->session)
						== GNUTLS_CRT_KRB) &&
					(0 != krb5_copy_principal (
						krbctx_cli,
						tgt->server,
						&cmd->krbid_srv))) {
				krb5_free_creds (krbctx_cli, ticket);
				gtls_errno = GNUTLS_E_NO_CERTIFICATE_FOUND;
				break;
			}
			krb5_free_creds (krbctx_cli, tgt);
			tgt = NULL;
			if (0 != krb5_copy_keyblock_contents (
					krbctx_cli,
					&ticket->keyblock,
					&cmd->krb_key)) {
				gtls_errno = GNUTLS_E_NO_CERTIFICATE_FOUND;
				// continue, with E_g2e() skipping import
			}
			certdatum.data = ticket->ticket.data;
			certdatum.size = ticket->ticket.length;
			E_g2e ("MOVED: Failed to import Kerberos ticket",
				gnutls_pcert_import_krb_raw (
					*pcert,
					&certdatum,
					0));
			krb5_free_creds (krbctx_cli, ticket);
		} else {
			//
			// For KDH-Only, the server supplies one of:
			//  - a TGT for user-to-user mode (for p2p exchanges)
			//  - an DER NULL to waive u2u mode
			//TODO// E_g2e ("MOVED: Failed to import Kerberos ticket",
			//TODO// 	gnutls_pcert_import_krb_raw (
			//TODO// 		*pcert,
			//TODO// 		&certdatum,	//TODO:WHATSFOUND//
			//TODO// 		0));
			int u2u = 0;
			int status = 0;
			krb5_creds *tgt = NULL;
			//
			// Determine whether we want to run in user-to-user mode
			// for which we should supply a TGT to the TLS client
			u2u = u2u || ((PIOF_STARTTLS_BOTHROLES_PEER & ~cmd->cmd.pio_data.pioc_starttls.flags) == 0);
			u2u = u2u || (strchr (rid, '@') != NULL);
			// u2u = u2u || "shaken hands on TLS symmetry extension"
			u2u = u2u && got_cc_srv;  // We may simply not be able!
			//
			// When not in user-to-user mode, deliver DER NULL
			if (!u2u) {
				certdatum.data = "\x05\x00";
				certdatum.size = 2;
				E_g2e ("Failed to withhold Kerberos server ticket",
					gnutls_pcert_import_krb_raw (
						*pcert,
						&certdatum,
						0));
				break;
			}
			//
			// Continue specifically for user-to-user mode.
			//TODO// Setup server principal identity
			//
			// Fetch the service's key
			status = have_key_tgt_cc (
				cmd, krbctx_srv,
				1, 0, 0,	// Hmm... later we know kvno/etype
				p11priv,
				krb_kt_srv,
				&cmd->krb_key, &tgt, NULL);
			if (status == 1) {
				// There's no use in having just the key
				krb5_free_keyblock_contents (krbctx_srv, &cmd->krb_key);
				memset (&cmd->krb_key, 0, sizeof (cmd->krb_key));
			}
			if (status < 2) {
				gtls_errno = GNUTLS_E_NO_CERTIFICATE_FOUND;
			} else if (0 != krb5_copy_principal (
						krbctx_srv, 
						tgt->server, 
						&cmd->krbid_srv)) {
				gtls_errno = GNUTLS_E_NO_CERTIFICATE_FOUND;
			}
			certdatum.data = tgt->ticket.data;
			certdatum.size = tgt->ticket.length;
			E_g2e ("Failed to withhold Kerberos server ticket",
				gnutls_pcert_import_krb_raw (
					*pcert,
					&certdatum,
					0));
			krb5_free_creds (krbctx_cli, tgt);
			tgt = NULL;
		}
		break;
#endif
	default:
		/* Should not happen */
		break;
	}

//TODO// Moved out (end)

#ifdef ANCIENT_CODE_WHEN_DBERRNO_RAN_IN_PARALLEL
	//
	// Lap up any overseen POSIX error codes in errno
	if (errno) {
		tlog (TLOG_TLS, LOG_DEBUG, "Failing TLS on errno=%d / %s", errno, strerror (errno));
		cmd->session_errno = errno;
		gtls_errno = GNUTLS_E_NO_CIPHER_SUITES;	/* Vaguely matching */
	}
#endif

	//
	// Return the overral error code, hopefully GNUTLS_E_SUCCESS
	tlog (TLOG_TLS, LOG_DEBUG, "Returning %d / %s from clisrv_cert_retrieve()", gtls_errno, gnutls_strerror (gtls_errno));
fprintf (stderr, "DEBUG: clisrv_cert_retrieve() sets *pcert to 0x%xl (length %d)... {pubkey = 0x%lx, cert= {data = 0x%lx, size=%ld}, type=%ld}\n", (long) *pcert, *pcert_length, (long) (*pcert)->pubkey, (long) (*pcert)->cert.data, (long) (*pcert)->cert.size, (long) (*pcert)->type);
	return gtls_errno;
}

/* Load a single certificate in the given gnutls_pcert_st from the given
 * gnutls_datum_t.  Use the lidtype to determine how to do this.
 */
gtls_error load_certificate (int lidtype, gnutls_pcert_st *pcert, gnutls_datum_t *certdatum) {
	int gtls_errno = GNUTLS_E_SUCCESS;
	//
	// Setup public key certificate
	switch (lidtype) {
	case LID_TYPE_X509:
fprintf (stderr, "DEBUG: About to import %d bytes worth of X.509 certificate into chain: %02x %02x %02x %02x...\n", certdatum->size, certdatum->data[0], certdatum->data[1], certdatum->data[2], certdatum->data[3]);
		E_g2e ("Failed to import X.509 certificate into chain",
			gnutls_pcert_import_x509_raw (
				pcert,
				certdatum,
				GNUTLS_X509_FMT_DER,
				0));
		break;
	case LID_TYPE_PGP:
		E_g2e ("Failed to import OpenPGP certificate",
			gnutls_pcert_import_openpgp_raw (
				pcert,
				certdatum,
				GNUTLS_OPENPGP_FMT_RAW,
				NULL,	/* use master key */
				0));
		break;
	case LID_TYPE_KRB5:
		/* Binary information is currently moot, so do not load it */
		break;
	default:
		/* Should not happen */
		break;
	}
	return gtls_errno;
}


/* Load a certificate chain.  This returns a value for a retrieval function's
 * pcert, and also modifies the chainlen.  The latter starts at 0, and is
 * incremented in a nested procedure that unrolls until all certificates are
 * loaded.
 */
gnutls_pcert_st *load_certificate_chain (uint32_t flags, unsigned int *chainlen, gnutls_datum_t *certdatum) {
	gnutls_pcert_st *chain;
	unsigned int mypos = *chainlen;
	int gtls_errno = GNUTLS_E_SUCCESS;

	//
	// Quick and easy: No chaining required, just add the literal data.
	// Note however, this may be the end of a chain, so allocate all
	// structures and load the single one at the end.
	if ((flags & (LID_CHAINED | LID_NEEDS_CHAIN)) == 0) {
		(*chainlen)++;
		chain = (gnutls_pcert_st *) calloc (*chainlen, sizeof (gnutls_pcert_st));
		if (chain != NULL) {
			memset (chain,
				0,
				(*chainlen) * sizeof (gnutls_pcert_st));
		} else {
			gtls_errno = GNUTLS_E_MEMORY_ERROR;
		}
		E_g2e ("Failed to load certificate into chain",
			load_certificate (
				flags & LID_TYPE_MASK,
				&chain [mypos],
				certdatum));
		if (gtls_errno != GNUTLS_E_SUCCESS) {
			if (chain) {
				free (chain);
			}
			*chainlen = 0;
			chain = NULL;
		}
		return chain;
	}

	//
	// First extended case.  Chain certs in response to LID_CHAINED.
	// Recursive calls are depth-first, so we only add our first cert
	// after a recursive call succeeds.  Any LID_NEEDS_CHAIN work is
	// added after LID_CHAINED, so is higher up in the hierarchy, but
	// it is loaded as part of the recursion.  To support that, a
	// recursive call with certdatum.size==0 is possible when the
	// LID_NEEDS_CHAIN flag is set, and this section then skips.
	// Note that this code is also used to load the certificate chain
	// provided by LID_NEEDS_CHAIN, but by then the flag in a recursive
	// call is replaced with LID_CHAINED and no more LID_NEEDS_CHAIN.
	if (((flags & LID_CHAINED) != 0) && (certdatum->size > 0)) {
		long certlen;
		int lenlen;
		gnutls_datum_t nextdatum;
		long nextlen;
		// Note: Accept BER because the outside SEQUENCE is not signed
		certlen = asn1_get_length_ber (
			((char *) certdatum->data) + 1,
			certdatum->size,
			&lenlen);
		certlen += 1 + lenlen;
		tlog (TLOG_CERT, LOG_DEBUG, "Found LID_CHAINED certificate size %d", certlen);
		if (certlen > certdatum->size) {
			tlog (TLOG_CERT, LOG_ERR, "Refusing LID_CHAINED certificate beyond data size %d", certdatum->size);
			*chainlen = 0;
			return NULL;
		} else if (certlen <= 0) {
			tlog (TLOG_CERT, LOG_ERR, "Refusing LID_CHAINED certificate of too-modest data size %d", certlen);
			*chainlen = 0;
			return NULL;
		}
		nextdatum.data = ((char *) certdatum->data) + certlen;
		nextdatum.size =           certdatum->size  - certlen;
		certdatum->size = certlen;
		nextlen = asn1_get_length_ber (
			((char *) nextdatum.data) + 1,
			nextdatum.size,
			&lenlen);
		nextlen += 1 + lenlen;
		if (nextlen == nextdatum.size) {
			// The last cert is loaded thinking it is not CHAINED,
			// but NEEDS_CHAIN can still be present for expansion.
			flags &= ~LID_CHAINED;
		}
		(*chainlen)++;
		chain = load_certificate_chain (flags, chainlen, &nextdatum);
		if (chain != NULL) {
			E_g2e ("Failed to add chained certificate",
				load_certificate (
					flags & LID_TYPE_MASK,
					&chain [mypos],
					certdatum));
			if (gtls_errno != GNUTLS_E_SUCCESS) {
				free (chain);
				chain = NULL;
				*chainlen = 0;
			}
		}
		return chain;
	}

	//
	// Second extended case.  Chain certs in response to LID_NEEDS_CHAIN.
	// These are the highest-up in the hierarchy, above any LID_CHAINED
	// certificates.  The procedure for adding them is looking them up
	// in a central database by their authority key identifier.  What is
	// found is assumed to be a chain, and will be unrolled by replacing
	// the LID_NEEDS_CHAIN flag with LID_CHAINED and calling recursively.
	if (((flags & LID_NEEDS_CHAIN) != 0) && (certdatum->size == 0)) {
		//TODO//CODE// lookup new certdatum
		flags &= ~LID_NEEDS_CHAIN;
		flags |=  LID_CHAINED;
		//TODO//CODE// recursive call
		//TODO//CODE// no structures to fill here
		//TODO//CODE// cleanup new certdatum
	}

	//
	// Final judgement.  Nothing worked.  Return failure.
	*chainlen = 0;
	return NULL;
}



/********** KERBEROS SUPPORT FUNCTIONS FOR TLS-KDH **********/



/* Prepare the Kerberos resources for use by clients and/or servers.
 */
#ifdef HAVE_TLS_KDH
static int setup_starttls_kerberos (void) {
	int k5err = 0;
	char *cfg;
	int retval = GNUTLS_E_SUCCESS;
	krb5_ccache krb_cc_tmp;
	const char *cctype_cli = NULL;
	const char *cctype_srv = NULL;
	//
	// Initialise
	krbctx_cli = krbctx_srv = NULL;
	krb_kt_cli = krb_kt_srv = NULL;
	got_cc_cli = got_cc_srv = 0;
	//
	// Construct credentials caching for Kerberos
	if (k5err == 0) {
		k5err = krb5_init_context (&krbctx_cli);
	}
	if (k5err == 0) {
		k5err = krb5_init_context (&krbctx_srv);
	}
	//
	// Load the various configuration variables
	cfg = cfg_krb_client_keytab ();
	if ((k5err == 0) && (cfg != NULL)) {
		k5err = krb5_kt_resolve (krbctx_cli, cfg, &krb_kt_cli);
	}
	cfg = cfg_krb_server_keytab ();
	if ((k5err == 0) && (cfg != NULL)) {
		k5err = krb5_kt_resolve (krbctx_srv, cfg, &krb_kt_srv);
	}
	cfg = cfg_krb_client_credcache ();
#if 0  /* Temporary bypass of cctype checks */
	if ((k5err == 0) && (cfg != NULL)) {
		k5err = krb5_cc_set_default_name (krbctx_cli, cfg);
		if (k5err == 0) {
			k5err = krb5_cc_default (krbctx_cli, &krb_cc_tmp);
		}
		if (k5err == 0) {
			got_cc_cli = 1;
			cctype_cli = krb5_cc_get_type (krbctx_cli, krb_cc_tmp);
			krb5_cc_close (krbctx_cli, krb_cc_tmp);
		}
	}
#endif
	cfg = cfg_krb_server_credcache ();
#if 0  /* Temporary bypass of cctype checks */
	if ((k5err == 0) && (cfg != NULL)) {
		k5err = krb5_cc_set_default_name (krbctx_srv, cfg);
		if (k5err == 0) {
			k5err = krb5_cc_default (krbctx_srv, &krb_cc_tmp);
		}
		if (k5err == 0) {
			got_cc_srv = 1;
			cctype_srv = krb5_cc_get_type (krbctx_cli, krb_cc_tmp);
			krb5_cc_close (krbctx_srv, krb_cc_tmp);
		}
	}
#endif
	//
	// Check for consistency and log helpful messages for the sysop
	if (k5err != 0) {
		tlog (TLOG_DAEMON | TLOG_KERBEROS, LOG_ERR, "Error during STARTTLS setup: %s (acting on %s)",
				krb5_get_error_message (krbctx_cli, k5err),
				cfg);
		retval = GNUTLS_E_UNWANTED_ALGORITHM;
	}
	if (krb_kt_cli != NULL) {
		tlog (TLOG_DAEMON | TLOG_KERBEROS, LOG_WARNING, "Ignoring the configured kerberos_client_keytab -- it is not implemented yet");
	}
	if (krb_kt_srv == NULL) {
		tlog (TLOG_DAEMON | TLOG_KERBEROS, LOG_ERR, "No kerberos_server_keytab configured, so Kerberos cannot work at all");
		retval = GNUTLS_E_UNWANTED_ALGORITHM;
/* TODO: Only for MIT krb5 1.11 and up
	} else if (0 == krb5_kt_have_content (krb_ctx, krb_kt_srv)) {
		tlog (TLOG_DAEMON | TLOG_KERBEROS, LOG_ERR, "Keytab in kerberos_server_keytab is absent or empty");
		retval = GNUTLS_E_UNWANTED_ALGORITHM;
 */
	}
	if (krbctx_cli == NULL) {
		tlog (TLOG_DAEMON | TLOG_KERBEROS, LOG_ERR, "No kerberos_client_credcache configured, so Kerberos cannot work at all");
		retval = GNUTLS_E_UNWANTED_ALGORITHM;
#if 0  /* Temporary bypass of cctype checks */
	} else if (!krb5_cc_support_switch (
			krbctx_cli, cctype_cli)) {
		tlog (TLOG_DAEMON | TLOG_KERBEROS, LOG_ERR, "Your kerberos_client_credcache does not support multilpe identities");
		retval = GNUTLS_E_UNWANTED_ALGORITHM;
#endif
	}
	if (krbctx_srv == NULL) {
		tlog (TLOG_DAEMON | TLOG_KERBEROS, LOG_WARNING, "No kerberos_server_credcache configured, so user-to-user Kerberos will not work");
#if 0  /* Temporary bypass of cctype checks */
	} else if (!krb5_cc_support_switch (
			krbctx_srv, cctype_srv)) {
		tlog (TLOG_DAEMON | TLOG_KERBEROS, LOG_ERR, "Your kerberos_server_credcache does not support multilpe identities");
		retval = GNUTLS_E_UNWANTED_ALGORITHM;
#endif
	}
	if (retval != GNUTLS_E_SUCCESS) {
		cleanup_starttls_kerberos ();
	}
	return retval;
}
#endif


/* Cleanup Kerberos resources.  This must be an idempotent function, because
 * it is called when Kerberos panics as well as when 
 */
#ifdef HAVE_TLS_KDH
static void cleanup_starttls_kerberos (void) {
	if (krb_kt_srv != NULL) {
		krb5_kt_close (krbctx_srv, krb_kt_srv);
		krb_kt_srv = NULL;
	}
	if (krb_kt_cli != NULL) {
		krb5_kt_close (krbctx_cli, krb_kt_cli);
		krb_kt_cli = NULL;
	}
	if (krbctx_srv != NULL) {
		krb5_free_context (krbctx_srv);
		krbctx_srv = NULL;
	}
	if (krbctx_cli != NULL) {
		krb5_free_context (krbctx_cli);
		krbctx_cli = NULL;
	}
}
#endif


/* Prompter callback function for PKCS #11.
 *
 * TODO: Use "struct pkcs11iter" as data, possibly interact with the user,
 * and keep a score on where we stand with password entry and changes.
 * Create clisrv_p11krb_setup() and clisrv_p11krb_cleanup() functions.
 *
 * In the current release for Kerberos, we have a very minimal mode for
 * doing this.  We may embellish it later or, preferrably, turn to a more
 * PKCS #11 styled approach, perhaps PKINIT or FAST.
 */
#ifdef HAVE_TLS_KDH
static krb5_error_code clisrv_p11krb_callback (krb5_context ctx,
					void *vcmd,
					const char *name,
					const char *banner,
					int num_prompts,
					krb5_prompt prompts []) {
	struct command *cmd = (struct command *) vcmd;
	int i;
	krb5_prompt_type *codes = krb5_get_prompt_types (ctx);
	int attempt = 0;
	static const char *token_url = "pkcs11:manufacturer=Kerberos+infrastructure;model=TLS+Pool;serial=%28none%29";
	static const char *token_label = "Kerberos infrastructure";
	for (i=0; i<num_prompts; i++) {
		//
		// Visit each prompt in turn, setting responses or return failure
		switch (codes [i]) {
		case KRB5_PROMPT_TYPE_PASSWORD:
			//TODO// Read a password from PKCS #11
			//TODO// Do we need to cycle passwords to cover retry?
			//TODO// Delete any failed passwords?
			//TODO:FIXED//
			if (attempt >= MAX_P11ITER_ATTEMPTS) {
				return KRB5_LIBOS_CANTREADPWD;
			}
			// Nothing in PKCS #11 --> so fallback on manual entry
			if (!pin_callback (attempt,
					token_url, "Enter Kerberos password:",
					prompts [i].reply->data,
					prompts [i].reply->length)) {
				memset (prompts [i].reply->data, 0, prompts [i].reply->length);
				return KRB5_LIBOS_CANTREADPWD;
			}
			//TODO// Manage data structure
			prompts [i].reply->length = strlen (prompts [i].reply->data);
			return 0;
		case KRB5_PROMPT_TYPE_NEW_PASSWORD:
		case KRB5_PROMPT_TYPE_NEW_PASSWORD_AGAIN:
			//TODO// Setup new password in PKCS #11
		case KRB5_PROMPT_TYPE_PREAUTH:
			//TODO// Use FAST, PKINIT, and so on...
		default:
			// Unrecognised and unimplemented prompt types end here
			return KRB5_LIBOS_CANTREADPWD;
		}
	}
	return 0;
}
#endif


/* Find a Kerberos keyblock and ticket to use for the localid.  Do not look
 * into services yet in this function.  This function implements a simple
 * procedure, based on optional arguments p11uri, keytab, credcache.  It
 * produces <key,tgt> or <key,NULL> or (for errors) <NULL,NULL>.
 *
 * The procedure followed, fully written out, is outlined below:
 *
 *	IF	have(credcache) AND acceptable (renewable) time
 *	THEN	RETURN <key,tgt>
 *	ELSE	IF have (keytab) AND found a suitable key
 *		THEN	IF have(credcache) and it works
 *			THEN	fetch cred tgt and key (auth with key in keytab)
 *				create credcache
 *				RETURN <key,tgt>
 *			ELSE	RETURN <key,NULL>
 *		ELSE	IF have(p11uri) AND it works
 *			THEN	fetch cred tgt and key (auth with pwd in p11uri)
 *				create credcache
 *				RETURN <key,tgt>
 *			ELSE	RETURN <NULL,NULL>
 *
 * The function returns a status value counting the number of values returned,
 * so 0 means error, 1 means key only and 2 means key and tgt.
 */
#ifdef HAVE_TLS_KDH
static int have_key_tgt_cc (struct command *cmd,	     // in, session context
				krb5_context ctx,    // in, kerberos context
				bool use_cc,         // in, whether to use cc
				krb5_kvno kvno,      // in, kvno (0 for highest)
				krb5_enctype enctype,// in, enctype (0 for any)
				char *p11uri,	     // in/opt, PKCS #11 pwd URI
				krb5_keytab kt,	     // in/opt, keytab
				krb5_keyblock *key,  // opt/opt session key
				krb5_creds **tgt,    // out/opt, tkt granting tkt
				krb5_ccache *cc) {   // out/opt, cred cache
	int k5err = 0;
	krb5_ccache newcc = NULL;
	krb5_principal sought  = NULL;
	krb5_principal sought1 = NULL;
	krb5_principal tgtname = NULL;
	krb5_keytab_entry ktentry;
	const char *svc = cmd->cmd.pio_data.pioc_starttls.service;
	const char *lid = cmd->cmd.pio_data.pioc_starttls.localid;
	const char *liddom;
	int lid1len;
	char **realms;
	char realm [128];
	uint32_t nametype, nametype_alt;
	time_t now = 0;
	//
	// Assertions, and initialise variables
	assert ( cmd != NULL);
	assert ( ctx != NULL);
	assert ( key != NULL);
	assert (*tgt == NULL);
	krb5_free_keyblock_contents (ctx, key);
	if (cc != NULL) {
		*cc = NULL;
	}
	//
	// Construct the realm name
	liddom = strrchr (lid, '@');
	if (liddom != NULL) {
		lid1len = ((intptr_t) liddom) - ((intptr_t) lid);
		liddom++;  // Skip '@'
	} else {
		liddom = lid;  // localid is a host
		lid1len = strnlen (lid, 128);
	}
	k5err = krb5_get_host_realm (ctx, liddom, &realms);
	if ((k5err == 0) && (realms [0] != NULL) && (*realms [0] != '\0')) {
		strncpy (realm, realms [0], sizeof (realm));
		realm [sizeof (realm)-1] = '\0';
	} else {
		int i = 0;
		do {
			realm [i] = toupper (liddom [i]);
			i++;
		} while (liddom [i-1] != '\0');
	}
	if (k5err == 0) {
		krb5_free_host_realm (ctx, realms);
	} else {
		k5err = 0;
	}
	//
	// Construct a sought principal name in a given naming style,
	// and try to locate it in the existing cache.
	// With @, try liduser@liddom@REALM or else liduser@REALM
	// Without @, try svc/liddom@REALM
	nametype = (lid == liddom) ? KRB5_NT_SRV_HST : KRB5_NT_ENTERPRISE_PRINCIPAL;
retry:
	nametype_alt = nametype;
	switch (nametype) {
	case KRB5_NT_ENTERPRISE_PRINCIPAL:
		nametype_alt = KRB5_NT_PRINCIPAL;
		k5err = krb5_build_principal_ext (ctx, &sought,
					strlen (realm), realm,
					strnlen (lid, 128), lid,
					0);
		break;
	case KRB5_NT_SRV_HST:
		if (strcmp (svc, "http") == 0) {
			svc = "HTTP";
		}
		k5err = krb5_build_principal_ext (ctx, &sought,
					strlen (realm), realm,
					strlen (svc), svc,
					lid1len, lid,
					0);
		break;
	case KRB5_NT_PRINCIPAL:
		k5err = krb5_build_principal_ext (ctx, &sought,
					strlen (realm), realm,
					lid1len, lid,
					0);
		break;
	}
	if (k5err == 0) {
		sought->type = nametype;
	} else {
		sought = NULL;
	}
	k5err = krb5_cc_cache_match (ctx, sought, &newcc);
	if (k5err != 0) {
		if ((nametype_alt != nametype) && (sought1 == NULL)) {
			nametype = nametype_alt;
			sought1  = sought;
			sought   = NULL;
			goto retry;
		}
		//
		// We failed to find an *existing* credentials cache
		// for the local identity.
		//
		// Our new hope is to create a fresh credential, and add
		// it to the current credcache.  To that end, we now try
		// to overrule k5err by getting hold of our default cc.
		goto from_scratch;
	}
	//
	// Construct the TGT name
	k5err = krb5_build_principal_ext (ctx, &tgtname,
				strlen (realm), realm,
				6, "krbtgt",
				strlen (realm), realm,
				0);
	if (k5err != 0) {
		tgtname = NULL;
		k5err = 0;
	}
	tgtname->type = KRB5_NT_SRV_INST;
	//
	// Try to get the service ticket for the TGT name from the cache
	krb5_creds credreq;
	memset (&credreq, 0, sizeof (credreq));
	credreq.client = sought;
	credreq.server = tgtname;
	k5err = krb5_get_credentials (ctx,
				/* KRB5_GC_USER_USER ?|? */
					( use_cc ? 0 : KRB5_GC_CACHED ),
				newcc,
				&credreq, tgt);
	time (&now);
	if ((k5err == 0)
				&& (now + 300 > (*tgt)->times.endtime)
				&& (now + 300 < (*tgt)->times.renew_till)) {
		//TODO:NOTHERE// krb5_free_creds (ctx, *tgt);
		//TODO:NOTHERE// *tgt = NULL;
		// Try to renew the ticket
		k5err = krb5_get_renewed_creds (ctx,
				*tgt,
				sought,
				newcc,
				NULL);   /* krbtgt/REALM@REALM */
	}
	if ((k5err == 0)
				&& (now + 300 > (*tgt)->times.endtime)) {
		// Thanks, but no thanks!
		krb5_free_creds (ctx, *tgt);
		*tgt = NULL;
		k5err = 666;
	}
	if (k5err == 0) {
		// First case worked -- return <key,tgt> from credout
		k5err = krb5_copy_keyblock_contents (ctx,
				&(*tgt)->keyblock,
				key);
		// On failure, key shows failure
		if (cc != NULL) {
			*cc = newcc;
			newcc = NULL;
		}
		goto cleanup;
	}
from_scratch:
	//
	// Prior attempts failed.  Instead, look for keytab or p11uri presence.
	// This is skipped when the use_cc option below welcomes krb5_creds.
	if ((key->contents == NULL) && (p11uri == NULL) && (kt == NULL)) {
		// We cannot obtain a new krbtgt
		// We simply return what we've got (which may be nothing)
		goto cleanup;
	}
	if ((kt == NULL) && (!use_cc)) {
		// We have nowhere to store a new krbtgt if we got it
		// We simply return what we've got (which is at least a key)
		goto cleanup;
	}
	//
	// Either we have a keytab key, or we have a p11uri,
	// so we can attempt to create a new credcache with a new krbtgt
	if (use_cc) {
		if (newcc == NULL) {
			k5err = krb5_cc_default (ctx, &newcc);
			if (k5err != 0) {
				// Utter failure to do even the simplest thing
				goto cleanup;
			}
		}
		*tgt = malloc (sizeof (**tgt));
		if (*tgt == NULL) {
			// Memory error
			goto cleanup;
		}
		memset (*tgt, 0, sizeof (**tgt));
		if ((sought != NULL) && (sought1 == NULL)) {
			// We only tried one name
			sought1 = sought;
			sought = NULL;
		}
		do {
			if (sought1 == NULL) {
				break;
			}
			if (p11uri == NULL) {
				k5err = krb5_get_init_creds_keytab (
						ctx,
						*tgt,
						sought1,
						kt,
						0,    /* start now please */
						NULL, /* get a TGT please */
						NULL);  //TODO// opts needed?
			} else {
				//TODO// Prepare PKCS #11 access
				k5err = krb5_get_init_creds_password (
						ctx,
						*tgt,
						sought1,
#ifdef TOM_IS_WEG
						NULL,	// Use callbacks for password
						clisrv_p11krb_callback,
#else
						"1234",
						NULL,
#endif
						cmd,  /* callback data pointer */
						0,    /* start now please */
						NULL, /* get a TGT please */
						NULL);  //TODO// opts needed?
				//TODO// End PKCS #11 access
			}
			krb5_free_principal (ctx, sought1);
			sought1 = sought;
			sought = NULL;
		} while (k5err != 0);
		if (k5err != 0) {
			// Failed to initiate new credentials
			krb5_free_creds (ctx, *tgt);
			*tgt = NULL;
			goto cleanup;
		}
		// Try to store the credential, if it was found
		if (sought1 != NULL) {
			k5err = krb5_cc_initialize (ctx, newcc, sought1);
			if (k5err == 0) {
				k5err = krb5_cc_store_cred (ctx, newcc, *tgt);
			}
		}
		// Copy the keyblock; any failure will show up in key
		krb5_copy_keyblock_contents (ctx,
			&(*tgt)->keyblock, //TODO:UNINIT// &ktentry.key,
			key);
		//
		// We succeeded in setting up a new Ticket Granting Ticket!
		if (cc != NULL) {
			*cc = newcc;
			newcc = NULL;
		}
		goto cleanup;
	}
	//
	// As a last resort, dig up a key directly from the keytab;
	// this is the only place where kvno and enctype are used
	if (kt != NULL) {
		//NOTE// Might be more direct as krb5_kt_read_service_key()
		k5err = krb5_kt_get_entry (
					ctx, kt,
					sought,
					kvno, enctype,
					&ktentry);
		if (k5err == 0) {
			k5err = krb5_copy_keyblock_contents (ctx,
				&ktentry.key,
				key);
			krb5_free_keytab_entry_contents (ctx, &ktentry);
			// On failure, key shows failure.
			if (cc != NULL) {
				*cc = newcc;
				newcc = NULL;
			}
			goto cleanup;
		}
	}
	//
	// Nothing more to try, so we continue into cleanup
cleanup:
	//
	// Cleanup and return the <key,tgt> values as they were delivered
	if (sought1 != NULL) {
		krb5_free_principal (ctx, sought1);
		sought1 = NULL;
	}
	if (sought != NULL) {
		krb5_free_principal (ctx, sought);
		sought = NULL;
	}
	if (tgtname != NULL) {
		krb5_free_principal (ctx, tgtname);
		tgtname = NULL;
	}
	if (newcc != NULL) {
		krb5_cc_close (ctx, newcc);
		newcc = NULL;
	}
	if (key->contents == NULL) {
		if (k5err != 0) {
			const char *errmsg = krb5_get_error_message (ctx, k5err);
			tlog (TLOG_DAEMON, LOG_ERR, "Kerberos error in have_key_tgt_cc: %s", errmsg);
			krb5_free_error_message (ctx, errmsg);
		}
		if (*tgt != NULL) {
			krb5_free_creds (ctx, *tgt);
			*tgt = NULL;
		}
		if ((cc != NULL) && (*cc != NULL)) {
			krb5_cc_close (ctx, *cc);
			*cc = NULL;
		}
		return 0;
	} else if (tgt == NULL) {
		if ((cc != NULL) && (*cc != NULL)) {
			krb5_cc_close (ctx, *cc);
			*cc = NULL;
		}
		return 1;
	} else if ((cc == NULL) || (*cc == NULL)) {
		return 2;
	} else {
		return 3;
	}
}
#endif


/* Have a ticket for the remote service.  Do this as a client.  The client
 * principal and realm are provided, and the ticket to be returned will
 * also provide the accompanying key.
 *
 * This function will incorporate the peer TGT, when it is provided.  This
 * is the case in KDH-Only exchanges with a non-empty Server Certificate.
 *
 * TODO: We are not currently serving backend tickets, but these could be
 * passed in as authorization data along with the credential request.
 * Note however, that authorization data is copied by default from the TGT,
 * but not necessarily from the request.  Not without KDC modifications.
 * But then again, the KDC should have responded with an error that it was
 * missing backend services; this is not something the client should decide
 * on, and certainly not after being requested by the service.  The error
 * and recovery could be implemented here (if we can get the error info out
 * of the libkrb5 API).  Alternatively, we might consider passing the
 * authorization data in the authenticator since we get to control it.
 * What will the specification say?
 *
 * The return value indicates how many of the requested output values have
 * been provided, counting from the first.  So, 0 means a total failure and
 * anything higher is a (partial) success.
 */
#ifdef HAVE_TLS_KDH
static int have_service_ticket (
				struct command *cmd,  // in, session context
				krb5_context ctx,     // in, kerberos context
				krb5_ccache cc_opt,   // in/opt, credcache
				krb5_principal cli,   // in, client principal
				krb5_creds **ticket) {// out, tkt granting tkt
	int k5err = 0;
	krb5_ccache cc = cc_opt;
	krb5_flags u2u = 0;
	krb5_principal srv = NULL;
	krb5_data tkt_srv;
	krb5_creds credreq;
	//
	// Sanity checks and initialisation
	memset (&tkt_srv, 0, sizeof (tkt_srv));
	memset (&credreq, 0, sizeof (credreq));
	*ticket = NULL;
	//
	// Determine the optional cc parameter if it was not provided
	//TODO// This can go if we always get it passed from have_key_tgt_cc()
	if (cc == NULL) {
		k5err = krb5_cc_cache_match (ctx, cli, &cc);
		if (k5err != 0) {
			goto cleanup;
		}
	}
	//
	// Build the server's principal name
	const char *svc = cmd->cmd.pio_data.pioc_starttls.service;
	const char *rid = cmd->cmd.pio_data.pioc_starttls.remoteid;
	const char *riddom;
	char **realms;
	char realm [128];
	riddom = strrchr (rid, '@');
	if (riddom != NULL) {
		riddom++;  // Skip '@'
	} else {
		riddom = rid;  // localid is a host
	}
	k5err = krb5_get_host_realm (ctx, riddom, &realms);
	if ((k5err == 0) && (realms [0] != NULL) && (*realms [0] != '\0')) {
		strncpy (realm, realms [0], sizeof (realm));
		realm [sizeof (realm)-1] = '\0';
	} else {
		int i = 0;
		do {
			realm [i] = toupper (riddom [i]);
			i++;
		} while (riddom [i-1] != '\0');
	}
	if (k5err == 0) {
		krb5_free_host_realm (ctx, realms);
	} else {
		k5err = 0;
	}
	if (strcmp (svc, "http") == 0) {
		svc = "HTTP";
	}
	k5err = krb5_build_principal_ext (ctx, &srv,
				strlen (realm), realm,
				strlen (svc), svc,
				strlen (rid), rid,
				0);
	if (k5err != 0) {
		goto cleanup;
	}
	srv->type = KRB5_NT_SRV_HST;
	//
	// Construct credential request
	credreq.client = cli;
	credreq.server = srv;
	//TODO// credreq.authdata may be used for backend service tickets
	//
	// See if our peer provided us with a TGT
	//  - we are sure of GNUTLS_CRD_CERTIFICATE because we implement it now
	//  - we must ensure that this is KDH-Only (remote GNUTLS_CRT_KRB)
	//  - we must ensure that the remote provided a non-empty ticket
	if (gnutls_certificate_type_get_peers (cmd->session) == GNUTLS_CRT_KRB) {
		// This is KDH-Only -- and the server may present a TGT
		const gnutls_datum_t *opt_srv_tkt;
		unsigned int srv_tkt_count;
		opt_srv_tkt = gnutls_certificate_get_peers (cmd->session, &srv_tkt_count);
		if ((opt_srv_tkt != NULL) && (srv_tkt_count >= 1) && (opt_srv_tkt [0].size > 5)) {
			// Looks good, we'll use only the first (normally only) one
			credreq.second_ticket.data   = opt_srv_tkt [0].data;
			credreq.second_ticket.length = opt_srv_tkt [0].size;
			u2u = KRB5_GC_USER_USER;
		}
	}
	//
	// Fetch the ticket for the service
	k5err = krb5_get_credentials (ctx, u2u, cc, &credreq, ticket);
	//
	// Cleanup and return; the return value depends on k5err
cleanup:
	if ((cc != NULL) && (cc_opt == NULL)) {
		//TODO// This can go if we always get it passed from have_key_tgt_cc()
		krb5_cc_close (ctx, cc);
		cc = NULL;
	}
	if (srv != NULL) {
		krb5_free_principal (ctx, srv);
	}
	return (k5err == 0) ? 1 : 0;
}
#endif


/* DER utility: This should probably appear in Quick DER sometime soon.
 *
 * Pack an Int32 or UInt32 and return the number of bytes.  Do not pack a header
 * around it.  The function returns the number of bytes taken, even 0 is valid.
 */
typedef uint8_t QDERBUF_INT32_T [4];
dercursor qder2b_pack_int32 (uint8_t *target_4b, int32_t value) {
	dercursor retval;
	int shift = 24;
	retval.derptr = target_4b;
	retval.derlen = 0;
	while (shift >= 0) {
		if ((retval.derlen == 0) && (shift > 0)) {
			// Skip sign-extending initial bytes
			uint32_t neutro = (value >> (shift - 1) ) & 0x000001ff;
			if ((neutro == 0x000001ff) || (neutro == 0x00000000)) {
				shift -= 8;
				continue;
			}
		}
		target_4b [retval.derlen] = (value >> shift) & 0xff;
		retval.derlen++;
		shift -= 8;
	}
	return retval;
}
typedef uint8_t QDERBUF_UINT32_T [5];
dercursor qder2b_pack_uint32 (uint8_t *target_5b, uint32_t value) {
	dercursor retval;
	int ofs = 0;
	if (value & 0x80000000) {
		*target_5b = 0x00;
		ofs = 1;
	}
	retval = qder2b_pack_int32 (target_5b + ofs, (int32_t) value);
	retval.derptr -= ofs;
	retval.derlen += ofs;
	return retval;
}


/* DER utility: This should probably appear in Quick DER sometime soon.
 *
 * Unpack an Int32 or UInt32 from a given number of bytes.  Do not assume a header
 * around it.  The function returns the value found.
 *
 * Out of range values are returned as 0.  This value only indicates invalid
 * return when len > 1, so check for that.
 */
int32_t qder2b_unpack_int32 (dercursor data4) {
	int32_t retval = 0;
	int idx;
	if (data4.derlen > 4) {
		goto done;
	}
	if ((data4.derlen > 0) && (0x80 & *data4.derptr)) {
		retval = -1;
	}
	for (idx=0; idx<data4.derlen; idx++) {
		retval <<= 8;
		retval += data4.derptr [idx];
	}
done:
	return retval;
}
uint32_t qder2b_unpack_uint32 (dercursor data5) {
	uint32_t retval = 0;
	int ofs = 0;
	if (data5.derlen > 5) {
		goto done;
	}
	if (data5.derlen == 5) {
		if (*data5.derptr != 0x00) {
			goto done;
		}
		// Modify the local copy on our stack
		data5.derlen--;
		data5.derptr++;
	}
	retval = (uint32_t) qder2b_unpack_int32 (data5);
done:
	return retval;
}


#ifdef HAVE_TLS_KDH
/* TODO: Debugging function for printing (descr,ptr,len) ranges */
static inline void prange (char *descr, uint8_t *ptr, int len) {
	fprintf (stderr, "%s #%04d: %02x %02x %02x %02x %02x %02x %02x %02x...%02x %02x %02x %02x\n",
			descr, len,
			ptr [0], ptr [1], ptr [2], ptr [3],
			ptr [4], ptr [5], ptr [6], ptr [7],
			ptr [len-4], ptr [len-3], ptr [len-2], ptr [len-1]);
}
static inline void prangefull (char *descr, uint8_t *ptr, int len) {
	fprintf (stderr, "%s #%04d:", descr, len);
	while (len-- > 0) {
		fprintf (stderr, " %02x", *ptr++);
	}
	fprintf (stderr, "\n");
}
#endif


/* The callback function that retrieves a TLS-KDH "signature", which is kept
 * outside of GnuTLS.  The callback computes an authenticator encrypted to
 * the session's Kerberos key.
 */
#ifdef HAVE_TLS_KDH
static gtls_error cli_kdhsig_encode (gnutls_session_t session,
			gnutls_datum_t *enc_authenticator,
			gnutls_datum_t *dec_authenticator,
			const gnutls_datum_t *hash,
			int32_t checksum_type) {
	//
	// Variables, sanity checking, initialisation
	struct command *cmd;
	int k5err = 0;
	authenticator_t auth;
	QDERBUF_INT32_T derv5;
	QDERBUF_INT32_T dernametype;
	QDERBUF_INT32_T dercksumtype;
	krb5_keyblock subkey;
	gnutls_certificate_type_t peercert;
	QDERBUF_INT32_T dersubkey;
	krb5_timestamp now_s;
	char derctime [100];
	krb5_int32 now_us;
	QDERBUF_INT32_T dercusec;
	cmd = (struct command *) gnutls_session_get_ptr (session);
	memset (&auth, 0, sizeof (auth));
	memset (&subkey, 0, sizeof (subkey));
	assert (cmd->krbid_cli != NULL);
	assert (cmd->krb_key.contents != NULL);
	static const uint8_t auth_packer [] = {
			DER_PACK_rfc4120_Authenticator, DER_PACK_END };
	static const uint8_t encdata_packer [] = {
			DER_PACK_rfc4120_EncryptedData, DER_PACK_END };
	//
	// Setup secure hash in authenticator (never optional for TLS-KDH)
	auth.cksum.cksumtype = qder2b_pack_int32 (dercksumtype, checksum_type);
	auth.cksum.checksum.derptr = hash->data;
	auth.cksum.checksum.derlen = hash->size;
	//
	// Optionally include a subkey (namely, for KDH-Only)
	peercert = gnutls_certificate_type_get_peers (session);
	if (peercert == GNUTLS_CRT_KRB) {
		// This is KDH-Only, for which we MUST create a random subkey
		k5err = krb5_c_make_random_key (
				krbctx_cli,
				ENCTYPE_AES256_CTS_HMAC_SHA1_96,
				&subkey);
		if (k5err != 0) {
			return GNUTLS_E_ENCRYPTION_FAILED;
		}
		auth.subkey.keytype = qder2b_pack_int32 (dersubkey, subkey.enctype);
		auth.subkey.keyvalue.derptr = subkey.contents;
		auth.subkey.keyvalue.derlen = subkey.length;
prange ("cli_K", subkey.contents, subkey.length);
	}
	//
	// Setup the client realm and principal name
	auth.crealm.derptr = cmd->krbid_cli->realm.data;
	auth.crealm.derlen = cmd->krbid_cli->realm.length;
	auth.cname.name_type = qder2b_pack_int32 (dernametype, cmd->krbid_cli->type);
	// The SEQUENCE OF with just one component is trivial to prepack
	auth.cname.name_string.derptr = cmd->krbid_cli->data [0].data;
	auth.cname.name_string.derlen = cmd->krbid_cli->data [0].length;
	//
	// Setup the Kerberos version number (5)
	auth.authenticator_vno = qder2b_pack_int32 (derv5, 5);
	//
	// Setup the obliged microsecond timer values (ignore error returns)
	krb5_us_timeofday (krbctx_cli, &now_s, &now_us);
	krb5_timestamp_to_string (now_s, derctime, sizeof (derctime));
	derctime [sizeof (derctime)-1] = '\0';
	auth.ctime.derptr = derctime;
	auth.ctime.derlen = strlen (derctime);
	auth.cusec = qder2b_pack_int32 (dercusec, now_us);
	//
	// Pack the decoded result into dec_authenticator
	size_t declen = der_pack (	auth_packer,
					(const dercursor *) &auth,
					NULL	// Measure length, no output yet
					);
	uint8_t *decptr = gnutls_malloc (declen);
	if (decptr == NULL) {
		return GNUTLS_E_MEMORY_ERROR;
	}
	der_pack (			auth_packer,
					(const dercursor *) &auth,
					decptr + declen);
	krb5_free_keyblock_contents (krbctx_cli, &subkey);
prangefull ("cli_A", decptr, declen);
	size_t rawlen;
	if (0 != krb5_c_encrypt_length (krbctx_cli,
					cmd->krb_key.enctype,
					declen,
					&rawlen)) {
		gnutls_free (decptr);
		return GNUTLS_E_ENCRYPTION_FAILED;
	}
	uint8_t *rawptr = gnutls_malloc (rawlen);
	if (rawptr == NULL) {
		gnutls_free (decptr);
		return GNUTLS_E_MEMORY_ERROR;
	}
	krb5_data decdata;
	krb5_enc_data rawdata;
	memset (&decdata, 0, sizeof (decdata));
	memset (&rawdata, 0, sizeof (rawdata));
	decdata.data   = decptr;
	decdata.length = declen;
	rawdata.ciphertext.data   = rawptr;
	rawdata.ciphertext.length = rawlen;
	if (0 != krb5_c_encrypt (	krbctx_cli,
					&cmd->krb_key,
					11 /* stealing key usage from AP-REQ */,
					NULL,
					&decdata,
					&rawdata)) {
		gnutls_free (rawptr);
		gnutls_free (decptr);
		return GNUTLS_E_ENCRYPTION_FAILED;
	}
	//
	// Prepare the header information
	QDERBUF_INT32_T deretype;
	QDERBUF_UINT32_T derkvno;
	encrypted_data_t encdata;
	memset (&encdata, 0, sizeof (encdata));
	encdata.etype = qder2b_pack_int32 (deretype, cmd->krb_key.enctype);
	//NOT// encdata.kvno  = qder2b_pack_int32 (derkvno,  cmd->krb_key.kvno);
	encdata.cipher.derptr = rawdata.ciphertext.data;
	encdata.cipher.derlen = rawdata.ciphertext.length;
	//
	// Prepare for packing the header and rawdata as EncryptedData
	size_t enclen = der_pack (	encdata_packer,
					(const dercursor *) &encdata,
					NULL	// Measure length, no output yet
					);
	uint8_t *encptr = gnutls_malloc (enclen);
	if (encptr == NULL) {
		gnutls_free (rawptr);
		gnutls_free (decptr);
		return GNUTLS_E_MEMORY_ERROR;
	}
	der_pack (			encdata_packer,
					(const dercursor *) &encdata,
					encptr + enclen);
	gnutls_free (rawptr);
	//
	// Return our final verdict on the generation of the Authenticator
	dec_authenticator->data = decptr;
	dec_authenticator->size = declen;
	enc_authenticator->data = encptr;
	enc_authenticator->size = enclen;
prange ("cli_D", decptr, declen);
prange ("cli_E", encptr, enclen);
	return 0;
}
#endif


/* The callback function that verifies a TLS-KDH "signature", which is kept
 * outside of GnuTLS.  The callback verifies the authenticator against the
 * provided session hash and returns the decrypted authenticator.
 */
#ifdef HAVE_TLS_KDH
static int srv_kdhsig_decode (gnutls_session_t session,
			const gnutls_datum_t *enc_authenticator,
			gnutls_datum_t *dec_authenticator,
			gnutls_datum_t *hash,
			int32_t *checksum_type) {
	//
	// Variables, sanity checks and initialisation
	int k5err = 0;
	struct command *cmd;
	static const uint8_t encdata_packer [] = {
		DER_PACK_rfc4120_EncryptedData, DER_PACK_END };
	static const uint8_t auth_packer [] = {
		DER_PACK_rfc4120_Authenticator, DER_PACK_END };
	encrypted_data_t encdata;
	cmd = (struct command *) gnutls_session_get_ptr (session);
prange ("srv_E", enc_authenticator->data, enc_authenticator->size);
	//
	// Retrieve the session key and store it in cmd->krb_key.
	//
	// Prior setting of cmd->krb_key would be due to user-to-user mode
	// having been setup with this as the server-supplied TGT key, in
	// which case cmd->krb_key would need to be overwritten by the
	// session key.
	//
	// When no prior cmd->krb_key is available, use the keytab to
	// decode the client's ticket.
	assert (gnutls_certificate_type_get_peers (session) == GNUTLS_CRT_KRB);
	const gnutls_datum_t *certs;
	unsigned int num_certs;
	certs = gnutls_certificate_get_peers (cmd->session, &num_certs);
	if (num_certs != 1) {
		return GNUTLS_E_NO_CERTIFICATE_FOUND;
	}
	krb5_data krbcert;
	krb5_ticket *tkt;
	krbcert.data   = certs [0].data;
	krbcert.length = certs [0].size;
prange ("srv_C", certs [0].data, certs [0].size);
	if (0 != krb5_decode_ticket (&krbcert, &tkt)) {
		return GNUTLS_E_NO_CERTIFICATE_FOUND;
	}
	if (cmd->krb_key.contents != NULL) {
		// user-to-user mode
		k5err = krb5_decrypt_tkt_part (
					krbctx_srv,
					&cmd->krb_key,
					tkt);
		krb5_free_keyblock_contents (
					krbctx_srv,
					&cmd->krb_key);
	} else {
		// client-to-server mode
		k5err = krb5_server_decrypt_ticket_keytab (
					krbctx_srv,
					krb_kt_srv,
					tkt);
	}
	if (k5err == 0) {
		k5err = krb5_copy_keyblock_contents (
					krbctx_srv,
					tkt->enc_part2->session,
					&cmd->krb_key);
	}
	if (k5err == 0) {
		k5err = krb5_copy_principal (
					krbctx_srv,
					tkt->enc_part2->client,
					&cmd->krbid_cli);
	}
	if (k5err == 0) {
		if (cmd->krbid_srv != NULL) {
			k5err = krb5_principal_compare (
							krbctx_srv,
							tkt->server,
							cmd->krbid_srv);
				// Server name changed since u2u setup => k5err
		} else {
			k5err = krb5_copy_principal (
							krbctx_srv,
							tkt->server,
							&cmd->krbid_srv);
		}
	}
	krb5_free_ticket (krbctx_srv, tkt);
	if (k5err != 0) {
		const char *errmsg = krb5_get_error_message (krbctx_srv, k5err);
		tlog (TLOG_DAEMON, LOG_ERR, "Kerberos error in srv_kdhsig_decode: %s", errmsg);
		krb5_free_error_message (krbctx_srv, errmsg);
		return GNUTLS_E_NO_CERTIFICATE_FOUND;
	}
	//
	// Harvest the EncryptedData fields from the enc_authenticator
	dercursor enctransport;
	enctransport.derptr = enc_authenticator->data;
	enctransport.derlen = enc_authenticator->size;
prangefull ("EncData2unpack", enctransport.derptr, enctransport.derlen);
	memset (&encdata, 0, sizeof (encdata));
	if (0 != der_unpack (		&enctransport,
					encdata_packer,
					(dercursor *) &encdata,
					1)) {
		tlog (TLOG_DAEMON, LOG_ERR, "Failed to der_unpack(EncryptedData) in server: %s", strerror (errno));
		return GNUTLS_E_DECRYPTION_FAILED;
	}
	if (encdata.kvno.derptr != NULL) {
		//TODO//NOTYET//ANDWHY// return GNUTLS_E_DECRYPTION_FAILED;
	}
	int32_t etype = qder2b_unpack_int32 (encdata.etype);
	//
	// Decrypt the EncryptedData fields into the dec_authenticator
	krb5_enc_data rawdata;
	krb5_data decdata;
	memset (&rawdata, 0, sizeof (rawdata));
	memset (&decdata, 0, sizeof (decdata));
	rawdata.enctype = etype;
	rawdata.ciphertext.data   = encdata.cipher.derptr;
	rawdata.ciphertext.length = encdata.cipher.derlen;
prange ("srv_R", encdata.cipher.derptr, encdata.cipher.derlen);
	decdata.data   = dec_authenticator->data;
	decdata.length = dec_authenticator->size;
	if (0 != krb5_c_decrypt (	krbctx_srv,
					&cmd->krb_key,
					11 /* stealing key usage from AP-REQ */,
					NULL,
					&rawdata,
					&decdata)) {
		return GNUTLS_E_DECRYPTION_FAILED;
	}
	dec_authenticator->size = decdata.length;
prange ("srv_D", decdata.data, decdata.length);
	//
	// Unpack the decrypted Authenticator
	dercursor decsyntax;
	decsyntax.derptr = decdata.data;
	decsyntax.derlen = decdata.length;
prangefull ("srv_A", decdata.data, decdata.length);
	authenticator_t auth;
	memset (&auth, 0, sizeof (auth));
	if (0 != der_unpack (		&decsyntax,
					auth_packer,
					(dercursor *) &auth,
					1)) {
		tlog (TLOG_DAEMON, LOG_ERR, "Failed to der_unpack(Authenticator) in server: %s", strerror (errno));
		return GNUTLS_E_DECRYPTION_FAILED;
	}
	//
	// Validate the contents of the Authenticator
	if (qder2b_unpack_int32 (auth.authenticator_vno) != 5) {
		return GNUTLS_E_DECRYPTION_FAILED;
	}
	if (auth.cksum.checksum.derptr == NULL) {
		return GNUTLS_E_DECRYPTION_FAILED;
	}
	if (auth.cksum.checksum.derlen < 16) {
		return GNUTLS_E_DECRYPTION_FAILED;
	}
	//TODO// Optionally, for KDH-Only, ensure presence and size of a subkey
	//
	// Produce the requested content from the Authenticator and return
	*checksum_type = qder2b_unpack_int32 (auth.cksum.cksumtype);
	hash->data = auth.cksum.checksum.derptr;
	hash->size = auth.cksum.checksum.derlen;
	return 0;
}
#endif



/********** VALIDATION EXPRESSION LINKUP TO GNUTLS **********/



/*
 * The following functions implement the various validation expression
 * components in terms of the GnuTLS sessions of this code file.
 * Some work is repeated in various expression variables, notably the
 * lookup of a session's peer credentials, and possibly importing them
 * into X.509 structures.  We may at some point decide to instead do
 * this ahead of time, ath the expense of some compleity and possibly
 * slow-down of the start of the computations.
 */



/* valexp_store_final -- store the valexp outcome in cmd->valexp_result.
 */
static void valexp_store_final (void *vcmd, struct valexp *ve, bool result) {
	((struct command *) vcmd)->valexp_result = result;
}

/* valexp_valflag_set -- set a validation flag bit for an uppercase predicate.
 */
static void valexp_valflag_set (struct command *cmd, char pred) {
	int len = strlen (cmd->valflags);
	cmd->valflags [len++] = pred;
	cmd->valflags [len  ] = '\0';
}

/* valexp_valflag_start -- get a prior set bit with validation information.
 * Where cmd->valflags is a string of uppercase letters that were ensured.
 */
static void valexp_valflag_start (void *vcmd, struct valexp *ve, char pred) {
	struct command *cmd = (struct command *) vcmd;
	pred &= 0xdf;	// lowercase->uppercase
	valexp_setpredicate (ve, pred, NULL != strchr (cmd->valflags, pred));
}

/* valexp_0_start -- validation function for the GnuTLS backend.
 * This function immediately sends failure on something impossible.
 */
static void valexp_0_start (void *vcmd, struct valexp *ve, char pred) {
	valexp_setpredicate (ve, pred, 0);
}

/* valexp_1_start -- validation function for the GnuTLS backend.
 * This function immediately sends success on something trivial.
 */
static void valexp_1_start (void *vcmd, struct valexp *ve, char pred) {
	valexp_setpredicate (ve, pred, 1);
}

//TODO// valexp_L_start, valexp_l_start

/* valexp_I_start -- validation function for the GnuTLS backend.
 * This function ensures that the remote peer provides an identity.
 * TODO: We should compare the hostname as well, or compare if in remoteid
 * TODO: We may need to support more than just X509/PGP certificates 
 */
static void valexp_I_start (void *vcmd, struct valexp *ve, char pred) {
	struct command *cmd = (struct command *) vcmd;
	int ok = 1;
	ok = ok && (cmd->remote_auth_type == GNUTLS_CRD_CERTIFICATE);
	ok = ok && (cmd->remote_cert_count > 0);
	// Accept most certificates, but not for example GNUTLS_CRT_RAW
	ok = ok && (
#ifdef GNUTLS_CRT_KRB
		(cmd->remote_cert_type == GNUTLS_CRT_KRB) ||
#endif
		(cmd->remote_cert_type == GNUTLS_CRT_X509) ||
		(cmd->remote_cert_type == GNUTLS_CRT_OPENPGP) );
	// peer-returned "certs" points into GnuTLS' internal data structures
	valexp_setpredicate (ve, pred, ok);
}

/* valexp_i_start -- is opportunistic and will always succeed
 */
#define valexp_i_start valexp_1_start

/* valexp_Ff_start -- validation function for the GnuTLS backend.
 * This functin ensures that forward secrecy is applied.
 * While _F_ only accepts DHE, _f_ will also accept DH.
 * Note: GnuTLS does not seem to show DH that is not also DHE.
 */
static void valexp_Ff_start (void *vcmd, struct valexp *ve, char pred) {
	struct command *cmd = (struct command *) vcmd;
	gnutls_kx_algorithm_t kx = gnutls_kx_get (cmd->session);
	switch (kx) {
	case GNUTLS_KX_UNKNOWN:
	case GNUTLS_KX_RSA:
	case GNUTLS_KX_RSA_EXPORT:
	case GNUTLS_KX_PSK:
	default:
		valexp_setpredicate (ve, pred, 0);
		break;
	case GNUTLS_KX_DHE_DSS:
	case GNUTLS_KX_DHE_RSA:
	case GNUTLS_KX_SRP:
	case GNUTLS_KX_SRP_RSA:
	case GNUTLS_KX_SRP_DSS:
	case GNUTLS_KX_DHE_PSK:
	case GNUTLS_KX_ECDHE_RSA:
	case GNUTLS_KX_ECDHE_ECDSA:
	case GNUTLS_KX_ECDHE_PSK:
	case GNUTLS_KX_ANON_ECDH:	// Assume DHE is in fact implemented
	case GNUTLS_KX_ANON_DH:		// Assume DHE is in fact implemented
		valexp_setpredicate (ve, pred, 1);
		break;
	// case GNUTLS_KX_xxx_DH:
	// 	valexp_setpredicate (ve, pred, pred != 'F');
	// 	break;
	}
}

/* valexp_A_start -- validation function for the GnuTLS backend.
 * This function ensures that an anonymising precursor is used.
 */
#define valexp_A_start valexp_valflag_start

/* valexp_a_start -- is opportunistic and will always succeed */
#define valexp_a_start valexp_1_start

/* valexp_Tt_start -- validation function for the GnuTLS backend.
 * This function ensures trust based on a trusted certificate/key list.
 * In the _t_ case, self-signed certificates are also accepted.
 */
static void valexp_Tt_start (void *vcmd, struct valexp *ve, char pred) {
	struct command *cmd = (struct command *) vcmd;
	int flagval = 0;
	unsigned int vfyresult;
	int bad;
	int i;
	if (cmd->vfystatus != 0) {
		goto setflagval;
	}
	if (cmd->remote_auth_type != GNUTLS_CRD_CERTIFICATE) {
		goto setflagval;
	}
	//
	// Handle self-signed peer certificates in a special way
	if (cmd->remote_cert_count == 1) {
		int bad = 0;
		bad = bad || (pred == 'T');	// Reject self-signed
		if (cmd->remote_cert_type == GNUTLS_CRT_X509) {
			vfyresult = 0;
			bad = bad || gnutls_x509_crt_verify (
				(gnutls_x509_crt_t   ) cmd->remote_cert [0],
				(gnutls_x509_crt_t *) &cmd->remote_cert [0], 1,
				GNUTLS_VERIFY_DISABLE_CA_SIGN,
				&vfyresult);
			// Apply the most stringent test.  This includes all of
			// GNUTLS_CERT_INVALID (always set, often with others)
			// GNUTLS_CERT_NOT_ACTIVATED
			// GNUTLS_CERT_EXPIRED
			// GNUTLS_CERT_SIGNER_CONSTRAINTS_FAILURE
			// GNUTLS_CERT_SIGNER_NOT_FOUND
			// GNUTLS_CERT_SIGNER_NOT_CA => oops...
			//	stopped with GNUTLS_VERIFY_DISABLE_CA_SIGN
			// GNUTLS_CERT_SIGNATURE_FAILURE
			// GNUTLS_CERT_INSECURE_ALGORITHM
			bad = bad || (vfyresult != 0);
			if (!bad) {
				flagval = 1;
				goto setflagval;
			}
		} else if (cmd->remote_cert_type == GNUTLS_CRT_OPENPGP) {
			//TODO// Prefer to actually check PGP self-signature
			//TODO// But only value is check private-key ownership
			flagval = 0;
			goto setflagval;
#ifdef GNUTLS_CRT_KRB
		} else if (cmd->remote_cert_type == GNUTLS_CRT_KRB) {
			// Kerberos has authenticated the ticket for us
			//TODO// Should we try reading from the ticket/auth?
			flagval = 1;
			goto setflagval;
#endif
		}
		if (bad) {
			goto setflagval;
		}
	}
	if (cmd->remote_cert_type == GNUTLS_CRT_X509) {
		// Now check the certificate chain, taking CA bits into account
		for (i=1; i<cmd->remote_cert_count; i++) {
			vfyresult = 0;
			bad = bad || gnutls_x509_crt_verify (
				(gnutls_x509_crt_t  )  cmd->remote_cert [i-1],
				(gnutls_x509_crt_t *) &cmd->remote_cert [i], 1,
				0,
				&vfyresult);
			// Apply the most stringent test.  This includes all of
			// GNUTLS_CERT_INVALID (always set, often with others)
			// GNUTLS_CERT_NOT_ACTIVATED
			// GNUTLS_CERT_EXPIRED
			// GNUTLS_CERT_SIGNER_CONSTRAINTS_FAILURE
			// GNUTLS_CERT_SIGNER_NOT_FOUND
			// GNUTLS_CERT_SIGNER_NOT_CA => oops...
			//	stopped with GNUTLS_VERIFY_DISABLE_CA_SIGN
			// GNUTLS_CERT_SIGNATURE_FAILURE
			// GNUTLS_CERT_INSECURE_ALGORITHM
			bad = bad || (vfyresult != 0);
		}
	} else if (cmd->remote_cert_type == GNUTLS_CRT_OPENPGP) {
		; //TODO// Check PGP direct signature (and also use in self-sig)
#ifdef GNUTLS_CRT_KRB
	} else if (cmd->remote_cert_type == GNUTLS_CRT_KRB) {
		; // Trust has already been validated through Kerberos
#endif
	}
setflagval:
	valexp_setpredicate (ve, pred, flagval);
}

/* valexp_Dd_start -- validation function for the GnuTLS backend.
 * This function validates through DNSSEC.
 * While _D_ enforces DNSSEC, _d_ also accepts opted-out security.
 */
static void valexp_Dd_start (void *vcmd, struct valexp *ve, char pred) {
	struct command *cmd = (struct command *) vcmd;
	int flagval = 0;
	dane_state_t stat;
	unsigned int vfystat;
	char *host;
	char *proto;
	int sox;
	struct sockaddr peername;
	socklen_t peernamesz = sizeof (peername);
	uint16_t port;
	host = strchr (cmd->cmd.pio_data.pioc_starttls.remoteid, '@');
	if (host == NULL) {
		host = cmd->cmd.pio_data.pioc_starttls.remoteid;
	}
	switch (cmd->cmd.pio_data.pioc_starttls.ipproto) {
	case IPPROTO_TCP:
		proto = "tcp";
		break;
	case IPPROTO_UDP:
		proto = "udp";
		break;
#ifndef WINDOWS_PORT
	case IPPROTO_SCTP:
		proto = "sctp";
		break;
#endif		
	default:
		goto setflagval;
	}
	sox = gnutls_transport_get_int (cmd->session);
	if (sox < 0) {
		goto setflagval;
	}
	if (getpeername (sox, &peername, &peernamesz) != 0) {
		goto setflagval;
	}
	if ((peername.sa_family == AF_INET) &&
				(peernamesz == sizeof (struct sockaddr_in))) {
		port = ntohs (((struct sockaddr_in *) &peername)->sin_port);
	} else if ((peername.sa_family == AF_INET6) &&
				(peernamesz == sizeof (struct sockaddr_in6))) {
	} else {
		port = ntohs (((struct sockaddr_in6 *) &peername)->sin6_port);
		goto setflagval;
	}
	//TODO// We might use online.c code instead?
	if (dane_state_init (&stat, /*TODO:*/ 0) != GNUTLS_E_SUCCESS) {
		goto setflagval;
	}
	if (dane_verify_session_crt (stat,
				cmd->session,
				host,
				proto,
				port,
				0,
				DANE_VFLAG_FAIL_IF_NOT_CHECKED,
				&vfystat) == DANE_E_SUCCESS) {
		if ((pred == 'D') && (vfystat & DANE_VERIFY_UNKNOWN_DANE_INFO)) {
			dane_state_deinit (stat);
			goto setflagval;
		}
		flagval = ((vfystat & ~DANE_VERIFY_UNKNOWN_DANE_INFO) == 0);
	}
	dane_state_deinit (stat);
setflagval:
	valexp_setpredicate (ve, pred, flagval);
}

/* valexp_Rr_start -- validation function for the GnuTLS backend.
 * This function validates through a CRL.
 * While _R_ requires the CRL to be present, _r_ accepts confirmed absense.
 * TODO: This is not implemented yet.
 */
static void valexp_Rr_start (void *vcmd, struct valexp *ve, char pred) {
	//TODO//;
	valexp_setpredicate (ve, pred, 0);
}

/* valexp_Ee_start -- validation function for the GnuTLS backend.
 * This function validates certificate extensions for the named service.
 * While _E_ required OIDs to be marked critical, _e_ also accepts non-crit.
 */
static void valexp_Ee_start (void *vcmd, struct valexp *ve, char pred) {
	//TODO//;
	valexp_setpredicate (ve, pred, 0);
}

/* valexp_Oo_start -- validation function for the GnuTLS backend.
 * This function validates with online/live information.
 * While _O_ required positive confirmation, _o_ also accepts unknown.
 *  -> For X.509,    look in OCSP or CRL or Global Directory
 *  -> For OpenPGP,  redirect O->G, o->g
 *  -> For Kerberos, accept anything as sufficiently live / online
 */
static void valexp_Oo_start (void *vcmd, struct valexp *ve, char pred) {
	struct command *cmd = (struct command *) vcmd;
	int valflag = 0;
	online2success_t o2vf;
	char *rid;
	gnutls_datum_t *raw;
	if (cmd->remote_auth_type != GNUTLS_CRD_CERTIFICATE) {
		// No authentication types other than certificates yet
		goto setvalflag;
	} else {
		if ((pred >= 'a') && (pred <= 'z')) {
			o2vf = online2success_optional;
		} else {
			o2vf = online2success_enforced;
		}
		rid = cmd->cmd.pio_data.pioc_starttls.remoteid;
		raw = (gnutls_datum_t *) cmd->remote_cert_raw;
		if (cmd->remote_cert_type == GNUTLS_CRT_OPENPGP) {
			valflag = o2vf (online_globaldir_pgp (
					rid,
					raw->data, raw->size));
		} else if (cmd->remote_cert_type == GNUTLS_CRT_X509) {
			// OCSP inquiry or globaldir
			valflag = o2vf (online_globaldir_x509 (
					rid,
					raw->data, raw->size));
#ifdef HAVE_TLS_KDH
		} else if (cmd->remote_cert_type == GNUTLS_CRT_KRB) {
			// Kerberos is sufficiently "live" to be pass O
			valflag = 1;
			goto setvalflag;
#endif
		} else {
			// GNUTLS_CRT_RAW, GNUTLS_CRT_UNKNOWN, or other
			goto setvalflag;
		}
	}
setvalflag:
	valexp_setpredicate (ve, pred, valflag);
}

/* valexp_Gg_start -- validation function for the GnuTLS backend.
 * This function validates through the LDAP global directory.
 * While _G_ requires information to be present, _g_ also accepts absense.
 *  -> For X.509,   lookup userCertificate
 *  -> For OpenPGP, lookup pgpKey
 *  -> For KDH,     lookup krbPrincipalName
 *  -> For SRP,     nothing is defined
 *  -> For OpenSSH, no TLS support
 */
static void valexp_Gg_start (void *vcmd, struct valexp *ve, char pred) {
	struct command *cmd = (struct command *) vcmd;
	int valflag = 0;
	online2success_t o2vf;
	char *rid;
	gnutls_datum_t *raw;
	if (cmd->remote_auth_type != GNUTLS_CRD_CERTIFICATE) {
		// No authentication types other than certificates yet
		goto setvalflag;
	} else {
		if ((pred >= 'a') && (pred <= 'z')) {
			o2vf = online2success_optional;
		} else {
			o2vf = online2success_enforced;
		}
		rid = cmd->cmd.pio_data.pioc_starttls.remoteid;
		raw = (gnutls_datum_t *) cmd->remote_cert_raw;
		if (cmd->remote_cert_type == GNUTLS_CRT_OPENPGP) {
			valflag = o2vf (online_globaldir_pgp (
					rid,
					raw->data, raw->size));
		} else if (cmd->remote_cert_type == GNUTLS_CRT_X509) {
			//TODO// OCSP inquiry or globaldir
			valflag = o2vf (online_globaldir_x509 (
					rid,
					raw->data, raw->size));
#ifdef GNUTLS_CRT_KRB
		} else if (cmd->remote_cert_type == GNUTLS_CRT_KRB) {
			valflag = 0;
			//TODO// valflag = o2vf (online_globaldir_kerberos (
			//TODO// 		rid,
			//TODO//		raw->data, raw->size));
#endif
		} else {
			// GNUTLS_CRT_RAW, GNUTLS_CRT_UNKNOWN, or other
			goto setvalflag;
		}
	}
setvalflag:
	valexp_setpredicate (ve, pred, valflag);
}

/* valexp_Pp_start -- validation function for the GnuTLS backend.
 * This function validates through pinning information.
 * While _P_ requires pinning to be present, _p_ will Trust On First Use.
 */
static void valexp_Pp_start (void *vcmd, struct valexp *ve, char pred) {
	//TODO//;
	valexp_setpredicate (ve, pred, 0);
}

/* valexp_U_start -- validation function for the GnuTLS backend.
 * This function validates a matching username.
 */
static void valexp_U_start (void *vcmd, struct valexp *ve, char pred) {
	//TODO//;
	valexp_setpredicate (ve, pred, 0);
}

/* valexp_Ss_start -- validation function for the GnuTLS backend.
 * This function ensures that the local end is a server.
 * While _S_ denies credentials also usable for clients, _s_ permits them.
 */
static void valexp_Ss_start (void *vcmd, struct valexp *ve, char pred) {
	struct command *cmd = (struct command *) vcmd;
	int flagval;
	if ((pred == 'S') && (cmd->cmd.pio_data.pioc_starttls.flags & PIOF_STARTTLS_LOCALROLE_CLIENT)) {
		flagval = 0;
	} else {
		flagval = (cmd->cmd.pio_data.pioc_starttls.flags & PIOF_STARTTLS_LOCALROLE_SERVER) != 0;
	}
	valexp_setpredicate (ve, pred, flagval);
}

/* valexp_Cc_start -- validation function for the GnuTLS backend.
 * This function ensures that the local end is a client.
 * While _C_ denies credentials also usable for servers, _c_ permits them.
 */
static void valexp_Cc_start (void *vcmd, struct valexp *ve, char pred) {
	struct command *cmd = (struct command *) vcmd;
	int flagval;
	if ((pred == 'C') && (cmd->cmd.pio_data.pioc_starttls.flags & PIOF_STARTTLS_LOCALROLE_SERVER)) {
		flagval = 0;
	} else {
		flagval = (cmd->cmd.pio_data.pioc_starttls.flags & PIOF_STARTTLS_LOCALROLE_CLIENT) != 0;
	}
	valexp_setpredicate (ve, pred, flagval);
}


static void valexp_error_start (void *handler_data, struct valexp *ve, char pred) {
	assert (0);
}
static void valexp_ignore_stop (void *handler_data, struct valexp *ve, char pred) {
	; // Nothing to do
}
static void valexp_ignore_final (void *handler_data, struct valexp *ve, bool value) {
	; // Nothing to do
}


/* Given a predicate, invoke its start routine.
 */
static void valexp_switch_start (void *handler_data, struct valexp *ve, char pred) {
	switch (pred) {
	case 'I':
		valexp_I_start (handler_data, ve, pred);
		break;
	case 'i':
		valexp_i_start (handler_data, ve, pred);
		break;
	case 'F':
	case 'f':
		valexp_Ff_start (handler_data, ve, pred);
		break;
	case 'A':
		valexp_A_start (handler_data, ve, pred);
		break;
	case 'a':
		valexp_a_start (handler_data, ve, pred);
		break;
	case 'T':
	case 't':
		valexp_Tt_start (handler_data, ve, pred);
		break;
	case 'D':
	case 'd':
		valexp_Dd_start (handler_data, ve, pred);
		break;
	case 'R':
	case 'r':
		valexp_Rr_start (handler_data, ve, pred);
		break;
	case 'E':
	case 'e':
		valexp_Ee_start (handler_data, ve, pred);
		break;
	case 'O':
	case 'o':
		valexp_Oo_start (handler_data, ve, pred);
		break;
	case 'G':
	case 'g':
		valexp_Gg_start (handler_data, ve, pred);
		break;
	case 'P':
	case 'p':
		valexp_Pp_start (handler_data, ve, pred);
		break;
	case 'U':
		valexp_U_start (handler_data, ve, pred);
		break;
	case 'S':
	case 's':
		valexp_Ss_start (handler_data, ve, pred);
		break;
	case 'C':
	case 'c':
		valexp_Cc_start (handler_data, ve, pred);
		break;
	default:
		// Called on an unregistered symbol, that spells failure
		valexp_setpredicate (ve, pred, 0);
		break;
	}
}

/* Return a shared constant structure for valexp_handling with GnuTLS.
 * This function does not fail; it always returns a non-NULL value.
 */
static const struct valexp_handling *have_starttls_validation (void) {
	static const struct valexp_handling starttls_valexp_handling = {
		.handler_start = valexp_switch_start,
		.handler_stop  = valexp_ignore_stop,
		.handler_final = valexp_store_final,
	};
	return &starttls_valexp_handling;
}



/* If any remote credentials are noted, cleanup on them.  This removes
 * any remote_cert[...] entries, counting up to remote_cert_count which
 * is naturally set to 0 initially, as well as after this has run.
 */
static void cleanup_any_remote_credentials (struct command *cmd) {
	while (cmd->remote_cert_count > 0) {
		gnutls_x509_crt_deinit (
			cmd->remote_cert [--cmd->remote_cert_count]);
	}
	memset (cmd->remote_cert, 0, sizeof (cmd->remote_cert));
}

/* Fetch remote credentials.  This can be done after TLS handshaking has
 * completed, to find the certificates or other credentials provided by
 * the peer to establish its identity.  The validation expression routines
 * can then refer to this resource, and won't have to request the same
 * information over and over again.  To this end, the information is stored
 * in the session object.  The arrays in which this information is stored
 * are size-constrained, but that is also a good security precaution.
 *
 * The information ends up in the following variables:
 *  - remote_auth_type
 *  - remote_cert_type (if remote_auth_type == GNUTLS_CRD_CERTIFICATE)
 *  - remote_cert[...] (if remote_cert_type == GNUTLS_CRD_CERTIFICATE)
 *  - remote_cert_count is the number of entries in remote_cert (up to root)
 *
 * When certificates are used, the root certificate is looked up, for
 * X.509 and PGP.
 *
 * After running successfully, a call to cleanup_any_remote_credentials()
 * must be called to clean up any data in the cmd structure.  This may be
 * done on cmd at any time after initialisation, even multiple times and
 * even when this call fails.  This call actually cleans up anything it
 * setup in the past, before setting up the data anew.
 */
static gtls_error fetch_remote_credentials (struct command *cmd) {
	gtls_error gtls_errno = GNUTLS_E_SUCCESS;
	const gnutls_datum_t *certs;
	unsigned int num_certs;
	gnutls_x509_crt_t x509peers [11]; // Peers + Root for GNUTLS_CRT_X509
	int i;
	bool got_chain = 0;
	int peer_tad = -1;

	// Did we run this before?  Then cleanup.
	cleanup_any_remote_credentials (cmd);
	//INVOLVES// memset (cmd->remote_cert, 0, sizeof (cmd->remote_cert));
	//INVOLVES// cmd->remote_cert_count = 0;
	// Prepare as-yet-unset default return values
	cmd->remote_auth_type = -1;
	cmd->remote_cert_raw = NULL;
	//
	// Obtain the authentication type for the peer
	cmd->remote_auth_type = gnutls_auth_get_type (cmd->session);
	switch (cmd->remote_auth_type) {
	case GNUTLS_CRD_CERTIFICATE:
		// Continue loading certificates in the GnuTLS format
		break;
	case GNUTLS_CRD_ANON:
		// No basis for any identity claim
		cmd->cmd.pio_data.pioc_starttls.remoteid [0] = '\0';
		return GNUTLS_E_SUCCESS;
	case GNUTLS_CRD_SRP:
		return GNUTLS_E_SUCCESS;
	case GNUTLS_CRD_PSK:
		return GNUTLS_E_SUCCESS;
	default:
		return GNUTLS_E_AUTH_ERROR;
	}
	//
	// Continue loading the certificate information: X.509, PGP, ...
#ifdef HAVE_TLS_KDH
	cmd->remote_cert_type = gnutls_certificate_type_get_peers (cmd->session);
	certs = gnutls_certificate_get_peers (cmd->session, &num_certs);
	// Note: server's certs _may_ be DER NULL due to mutual auth in Kerberos
#else
	cmd->remote_cert_type = gnutls_certificate_type_get (cmd->session);
	certs = gnutls_certificate_get (cmd->session, &num_certs);
#endif
	if (certs == NULL) {
		num_certs = 0;
	}
	// "certs" points into GnuTLS' internal data structures
	if ((num_certs < 1) || (num_certs > CERTS_MAX_DEPTH)) {
		return GNUTLS_E_AUTH_ERROR;
	}
	cmd->remote_cert_raw = (void *) &certs [0];
	//
	// Turn certificate data into GnuTLS' data structures (to be cleaned)
	if (cmd->remote_cert_type == GNUTLS_CRT_X509) {
		peer_tad = TAD_TYPE_X509;
		for (i=0; i < num_certs; i++) {
			E_g2e ("Failed to initialise peer X.509 certificate",
				gnutls_x509_crt_init (
					(gnutls_x509_crt_t *) &cmd->remote_cert [i]));
			if (gtls_errno == GNUTLS_E_SUCCESS) {
				cmd->remote_cert_count++;
			}
			E_g2e ("Failed to import peer X.509 certificate",
				gnutls_x509_crt_import (
					cmd->remote_cert [i],
					&certs [i], GNUTLS_X509_FMT_DER));
		}
		if (gtls_errno != GNUTLS_E_SUCCESS) {
			goto cleanup;
		}
	} else if (cmd->remote_cert_type == GNUTLS_CRT_OPENPGP) {
		peer_tad = TAD_TYPE_PGP;
		E_g2e ("Failed to initialise peer PGP key",
				gnutls_x509_crt_init (
					(gnutls_x509_crt_t *) &cmd->remote_cert [0]));
		if (gtls_errno == GNUTLS_E_SUCCESS) {
			cmd->remote_cert_count = 1;
		}
		E_g2e ("Failed to import peer PGP key",
				gnutls_openpgp_crt_import (
					cmd->remote_cert [0],
					&certs [0], GNUTLS_OPENPGP_FMT_RAW));
		if (gtls_errno != GNUTLS_E_SUCCESS) {
			goto cleanup;
		}
	}

	//
	// Lookup the trusted party that the peers certificates is promoting.
	// Note that even if the peer ends in a CA cert (which it may not
	// always send along) then we can still add it ourselves again :-)
	// Only worry might be that CA certs require no AuthorityKeyIdentifier.
	if (cmd->remote_cert_type == GNUTLS_CRT_X509) {
		// Retrieve the AuthorityKeyIdentifier from last (or semi-last)
		uint8_t id [100];
		size_t idsz;
		DBT rootca;
		DBT anchor;
		DBC *crs_trust = NULL;
		int db_errno;
		gnutls_datum_t anchor_gnutls;
		gnutls_x509_crt_t dbroot;
		dbt_init_empty (&rootca);
		dbt_init_empty (&anchor);
		idsz = sizeof (id);
		gtls_errno = gnutls_x509_crt_get_authority_key_id (
			cmd->remote_cert [cmd->remote_cert_count-1],
			id, &idsz,
			NULL);
		if (gtls_errno == GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE) {
			// Only retry if the last is a signer, possibly CA
			if (cmd->remote_cert_count == 1) {
				// Permit self-signed certificate evaluation
				gtls_errno = GNUTLS_E_SUCCESS;
			} else if (cmd->remote_cert_count > 1) {
				// Assume the last is a root cert, as it lacks authid
				gnutls_x509_crt_deinit (
					cmd->remote_cert [--cmd->remote_cert_count]);
				cmd->remote_cert [cmd->remote_cert_count] = NULL;
				idsz = sizeof (id);
				gtls_errno = gnutls_x509_crt_get_authority_key_id (
					cmd->remote_cert [cmd->remote_cert_count-1],
					id, &idsz,
					NULL);
			}
		}
		if (gtls_errno != GNUTLS_E_SUCCESS) {
			goto cleanup;
		}
		// Get root cert from trustdb into remote_cert [_count++]
		dbt_init_fixbuf (&rootca, id, idsz);
		dbt_init_malloc (&anchor);
		E_d2e ("Failed to create db_disclose cursor",
			dbh_trust->cursor (
				dbh_trust,
				cmd->txn,
				&crs_trust,
				0));
		E_d2e ("X.509 authority key identifier not found in trust database",
			dba_trust_iterate (
				crs_trust, &rootca, &anchor));
		while (db_errno == 0) {
			// Process "anchor" entry (inasfar as meaningful)
			uint32_t anchorflags;
			uint8_t *trustdata;
			int trustdatalen;
			char *valexp;	//TODO// Initiate this before cleanup
			int tstatus = trust_interpret (&anchor, &anchorflags, &valexp, &trustdata, &trustdatalen);
			dbt_free (&anchor);
			if (tstatus != TAD_STATUS_SUCCESS) {
				// Signal any DB error to bail out of this loop
				db_errno = DB_KEYEMPTY;
			} else if ((anchorflags & TAD_TYPE_MASK) != peer_tad) {
				;	// Skip unsought trust database entry
			} else if ((anchorflags & TAD_TYPE_MASK) == TAD_TYPE_X509) {
				E_g2e ("Certificate chain too long",
					(cmd->remote_cert_count >= CERTS_MAX_DEPTH)
					? GNUTLS_E_AUTH_ERROR
					: GNUTLS_E_SUCCESS);
				// Turn the anchor into an X.509 certificate
				E_g2e ("Failet to initialise X.509 peer trust anchor",
					gnutls_x509_crt_init ((gnutls_x509_crt_t *) &cmd->remote_cert [cmd->remote_cert_count]));
				if (gtls_errno == GNUTLS_E_SUCCESS) {
					cmd->remote_cert_count++;
					anchor_gnutls.data = anchor.data;
					anchor_gnutls.size = anchor.size;
					E_g2e ("Failed to import X.509 peer trust anchor",
						gnutls_x509_crt_import (cmd->remote_cert [cmd->remote_cert_count-1], &anchor_gnutls, GNUTLS_X509_FMT_DER));
				}
				if (gtls_errno == GNUTLS_E_SUCCESS) {
					// Everything worked, we have a chain
					got_chain = 1;
					if (cmd->trust_valexp) {
						free (cmd->trust_valexp);
					}
					cmd->trust_valexp = strdup (valexp);
				} else {
					// Signal arbitrary DB error
					db_errno = DB_KEYEMPTY;
				}
			} else if ((anchorflags & TAD_TYPE_MASK) == TAD_TYPE_REVOKE_X509) {
				//TODO// Possibly verify end cert revocation
			} else {
				/* Ignore entry, continue with the next */;
			}
			db_errno = dba_trust_iterate (crs_trust, &rootca, &anchor);
		}
		if (crs_trust != NULL) {
			crs_trust->close (crs_trust);
			crs_trust = NULL;
		}
		dbt_free (&anchor);
		// No dbt_free (&rootca) because it is set to a fixed buffer
		if (db_errno != DB_NOTFOUND) {
			goto cleanup;
		}
	} else if (cmd->remote_cert_type == GNUTLS_CRT_OPENPGP) {
		; //TODO// Attempt to load PGP direct signer(s)
		; //OPTION// May use the _count for alternative signers!
		; //OPTION// May setup/reload a keyring based on trust.db
#ifdef GNUTLS_CRT_KRB
	} else if (cmd->remote_cert_type == GNUTLS_CRT_KRB) {
		; //TODO// Process as appropriate for Kerberos (store Ticket?)
#endif
	}
	//
	// Cleanup (when returning an error code) and return
cleanup:
	if (gtls_errno != GNUTLS_E_SUCCESS) {
		cleanup_any_remote_credentials (cmd);
	}
	while ((!got_chain) && (cmd->remote_cert_count > 1)) {
		--cmd->remote_cert_count;
		gnutls_x509_crt_deinit (
			cmd->remote_cert [cmd->remote_cert_count]);
		cmd->remote_cert [cmd->remote_cert_count] = NULL;
	}
	return gtls_errno;
}


/* Fetch local credentials.  This can be done before TLS is started, to find
 * the possible authentication forms that can be offered.  The function
 * can additionally be used after interaction with the client to establish
 * a local identity that was not initially provided, or that was not
 * considered public at the time.
 */
gtls_error fetch_local_credentials (struct command *cmd) {
	int lidrole;
	char *lid, *rid;
	DBC *crs_disclose = NULL;
	DBC *crs_localid = NULL;
	DBT discpatn;
	DBT keydata;
	DBT creddata;
	selector_t remote_selector;
	int gtls_errno = 0;
	int db_errno = 0;
	int found = 0;
	gtls_error certificate_onthefly (struct command *cmd);

	//
	// When applicable, try to create an on-the-fly certificate
	if (((cmd->cmd.pio_cmd == PIOC_STARTTLS_V2) &&
			(cmd->cmd.pio_data.pioc_starttls.flags & PIOF_STARTTLS_LOCALID_ONTHEFLY))
	|| ((cmd->cmd.pio_cmd == PIOC_LIDENTRY_CALLBACK_V2) &&
			(cmd->cmd.pio_data.pioc_lidentry.flags & PIOF_LIDENTRY_ONTHEFLY))) {
		gtls_errno = certificate_onthefly (cmd);
		if (gtls_errno != GNUTLS_E_AGAIN) {
			// This includes GNUTLS_E_SUCCESS
fprintf (stderr, "DEBUG: otfcert retrieval returned %d\n", gtls_errno);
			return gtls_errno;
		} else {
fprintf (stderr, "DEBUG: otfcert retrieval returned GNUTLS_E_AGAIN, so skip it\n", gtls_errno);
			gtls_errno = GNUTLS_E_SUCCESS;  // Attempt failed, ignore
		}
	}

	//
	// Setup a number of common references and structures
	// Note: Current GnuTLS cannot support being a peer
	if (cmd->cmd.pio_data.pioc_starttls.flags & PIOF_STARTTLS_LOCALROLE_CLIENT) {
		lidrole = LID_ROLE_CLIENT;
	} else if (cmd->cmd.pio_data.pioc_starttls.flags & PIOF_STARTTLS_LOCALROLE_SERVER) {
		lidrole = LID_ROLE_SERVER;
	} else {
		E_g2e ("TLS Pool command supports neither local client nor local server role",
			GNUTLS_E_INVALID_SESSION);
		return gtls_errno;
	}
	lid = cmd->cmd.pio_data.pioc_starttls.localid;
	rid = cmd->cmd.pio_data.pioc_starttls.remoteid;

	//
	// Refuse to disclose client credentials when the server name is unset;
	// note that server-claimed identities are unproven during handshake.
	if ((lidrole == LID_ROLE_CLIENT) && (*rid == '\0')) {
		tlog (TLOG_USER, LOG_ERR, "No remote identity (server name) set, so no client credential disclosure");
		E_g2e ("Missing remote ID",
			GNUTLS_E_NO_CERTIFICATE_FOUND);
		return gtls_errno;
	}
	//
	// Setup database iterators to map identities to credentials
	if (lidrole == LID_ROLE_CLIENT) {
		E_d2e ("Failed to create db_disclose cursor",
			dbh_disclose->cursor (
				dbh_disclose,
				cmd->txn,
				&crs_disclose,
				0));
	}
	E_d2e ("Failed to create db_localid cursor",
		dbh_localid->cursor (
			dbh_localid,
			cmd->txn,
			&crs_localid,
			0));
	//
	// Prepare for iteration over possible local identities / credentials
	char mid [128];
	char cid [128];
	if (gtls_errno != 0) {
		; // Skip setup
	} else if (lidrole == LID_ROLE_CLIENT) {
		memcpy (cid, rid, sizeof (cid));
		dbt_init_fixbuf (&discpatn, cid, strlen (cid));
		dbt_init_fixbuf (&keydata,  mid, sizeof (mid)-1);
		dbt_init_malloc (&creddata);
		selector_t ridsel;
		donai_t remote_donai = donai_from_stable_string (rid, strlen (rid));
		if (!selector_iterate_init (&remote_selector, &remote_donai)) {
			E_g2e ("Syntax of remote ID unsuitable for selector",
				GNUTLS_E_INVALID_REQUEST);
		} else {
			E_d2e ("Failed to start iterator on remote ID selector",
				dbcred_iterate_from_remoteid_selector (
					crs_disclose,
					crs_localid,
					&remote_selector,
					&discpatn,
					&keydata,
					&creddata));
		}
	} else {
		dbt_init_fixbuf (&discpatn, "", 0);	// Unused but good style
		dbt_init_fixbuf (&keydata,  lid, strlen (lid));
		dbt_init_malloc (&creddata);
		E_d2e ("Failed to start iterator on local ID",
			dbcred_iterate_from_localid (
			crs_localid,
			&keydata,
			&creddata));
	}
	if (db_errno != 0) {
		gtls_errno = GNUTLS_E_DB_ERROR;
	}

	//
	// Now store the local identities inasfar as they are usable
	db_errno = 0;
	while ((gtls_errno == GNUTLS_E_SUCCESS) && (db_errno == 0)) {
		int ok;
		uint32_t flags;
		int lidtype;

		tlog (TLOG_DB, LOG_DEBUG, "Found BDB entry %s disclosed to %s", creddata.data + 4, (lidrole == LID_ROLE_CLIENT)? rid: "all clients");
		ok = dbcred_flags (
			&creddata,
			&flags);
		lidtype = flags & LID_TYPE_MASK;
		ok = ok && ((flags & lidrole) != 0);
		ok = ok && ((flags & LID_NO_PKCS11) == 0);
		ok = ok && (lidtype >= LID_TYPE_MIN);
		ok = ok && (lidtype <= LID_TYPE_MAX);
#ifdef HAVE_TLS_KDH
		// For current/simple Kerberos, refuse data after PKCS #11 URI
		ok = ok && ((lidtype != LID_TYPE_KRB5) || (NULL == memchr (creddata.data + 4, '\0', creddata.size - 4 - 1)));
#endif
		tlog (TLOG_DB, LOG_DEBUG, "BDB entry has flags=0x%08x, so we (%04x/%04x) %s it", flags, lidrole, LID_ROLE_MASK, ok? "store": "skip ");
		if (ok) {
			if (cmd->lids [lidtype - LID_TYPE_MIN].data != NULL) {
				free (cmd->lids [lidtype - LID_TYPE_MIN].data);
			}
			// Move the credential into the command structure
			dbt_store (&creddata,
				&cmd->lids [lidtype - LID_TYPE_MIN]);
fprintf (stderr, "DEBUG: Storing cmd->lids[%d].data 0x%016x\n", lidtype-LID_TYPE_MIN, cmd->lids [lidtype-LID_TYPE_MIN].data);
			found = 1;
		} else {
			// Skip the credential by freeing its data structure
			dbt_free (&creddata);
		}
		db_errno = dbcred_iterate_next (crs_disclose, crs_localid, &discpatn, &keydata, &creddata);
	}

	if (db_errno == DB_NOTFOUND) {
		if (!found) {
			gtls_errno = GNUTLS_E_NO_CERTIFICATE_FOUND;
		}
	}
	if (crs_localid != NULL) {
		crs_localid->close (crs_localid);
		crs_localid = NULL;
	}
	if (crs_disclose != NULL) {
		crs_disclose->close (crs_disclose);
		crs_disclose = NULL;
	}
	return gtls_errno;
}


/*
 * Check if a given cmd has the given LID_TYPE setup.
 * Return 1 for yes or 0 for no; this is used in priority strings.
 */
static inline int lidtpsup (struct command *cmd, int lidtp) {
	return cmd->lids [lidtp - LID_TYPE_MIN].data != NULL;
}

/* Configure the GnuTLS session with suitable credentials and priority string.
 * The anonpre_ok flag should be non-zero to permit Anonymous Precursor.
 *
 * The credential setup is optional; when creds is NULL, no changes will
 * be made.
 */
static int configure_session (struct command *cmd,
			gnutls_session_t session,
			struct credinfo *creds,
			int credcount,
			int anonpre_ok) {
	int i;
	int gtls_errno = GNUTLS_E_SUCCESS;
	//
	// Install the shared credentials for the client or server role
	if (creds != NULL) {
		gnutls_credentials_clear (session);
		for (i=0; i<credcount; i++) {
			E_g2e ("Failed to install credentials into TLS session",
				gnutls_credentials_set (
					session,
					creds [i].credtp,
					creds [i].cred  ));
		}
	}
	//
	// Setup the priority string for this session; this avoids future
	// credential callbacks that ask for something impossible or
	// undesired.
	//
	// Variation factors:
	//  - starting configuration (can it be empty?)
	//  - Configured security parameters (database? variable?)
	//  - CTYPEs, SRP, ANON-or-not --> fill in as + or - characters
	if (gtls_errno == GNUTLS_E_SUCCESS) {
		char priostr [512];
#ifdef HAVE_TLS_KDH
		snprintf (priostr, sizeof (priostr)-1,
			// "NORMAL:-RSA:" -- also ECDH-RSA, ECDHE-RSA, ...DSA...
			"NONE:"
			"%%ASYM_CERT_TYPES:"
			"+VERS-TLS-ALL:+VERS-DTLS-ALL:"
			"+COMP-NULL:"
			"+CIPHER-ALL:+CURVE-ALL:+SIGN-ALL:+MAC-ALL:"
			"%cANON-ECDH:"
			"+ECDHE-KRB:" // +ECDHE-KRB-RSA:+ECDHE-KRB-ECDHE:" // opt?
			"+ECDHE-RSA:+DHE-RSA:+ECDHE-ECDSA:+DHE-DSS:+RSA:" //TODO//
			"+CTYPE-SRV-KRB:+CTYPE-SRV-X.509:+CTYPE-SRV-OPENPGP:"
			"%cCTYPE-CLI-KRB:"
			"%cCTYPE-CLI-X.509:"
			"%cCTYPE-CLI-OPENPGP:"
			"%cSRP:%cSRP-RSA:%cSRP-DSS",
			anonpre_ok				?'+':'-',
			1 /* lidtpsup (cmd, LID_TYPE_KRB5)*/		?'+':'-',
			1 /*lidtpsup (cmd, LID_TYPE_X509)*/		?'+':'-',
			1 /*lidtpsup (cmd, LID_TYPE_PGP)*/		?'+':'-',
			//TODO// Temporarily patched out SRP
			lidtpsup (cmd, LID_TYPE_SRP)		?'+':'-',
			lidtpsup (cmd, LID_TYPE_SRP)		?'+':'-',
			lidtpsup (cmd, LID_TYPE_SRP)		?'+':'-');
#else
		// It's not possible to make good decisions on certificate type
		// for both sides based on knowledge of local authentication
		// abilities.  So we permit all (but would like to be subtler).
		snprintf (priostr, sizeof (priostr)-1,
			// "NORMAL:-RSA:" -- also ECDH-RSA, ECDHE-RSA, ...DSA...
			"NONE:"
			"+VERS-TLS-ALL:+VERS-DTLS-ALL:"
			"+COMP-NULL:"
			"+CIPHER-ALL:+CURVE-ALL:+SIGN-ALL:+MAC-ALL:"
			"%cANON-ECDH:"
			"+ECDHE-RSA:+DHE-RSA:+ECDHE-ECDSA:+DHE-DSS:+RSA:" //TODO//
			"%cCTYPE-X.509:"
			"%cCTYPE-OPENPGP:"
			"%cSRP:%cSRP-RSA:%cSRP-DSS",
			anonpre_ok				?'+':'-',
			1		?'+':'-',
			1		?'+':'-',
			//TODO// Temporarily patched out SRP
			1		?'+':'-',
			1		?'+':'-',
			1		?'+':'-');
#endif
		tlog (TLOG_TLS, LOG_DEBUG, "Constructed priority string %s for local ID %s",
			priostr, cmd->cmd.pio_data.pioc_starttls.localid);
		E_g2e ("Failed to set GnuTLS priority string",
			gnutls_priority_set_direct (
			session,
			priostr,
			NULL));
	}
	//
	// Return the application GNUTLS_E_ code including _SUCCESS
	return gtls_errno;
}

/* The callback functions retrieve various bits of information for the client
 * or server in the course of the handshake procedure.
 *
 * The logic here is based on client-sent information, such as:
 *  - TLS hints -- X.509 or alternatives like OpenPGP, SRP, PSK
 *  - TLS hints -- Server Name Indication
 *  - User hints -- local and remote identities provided
 */
static int srv_clienthello (gnutls_session_t session, unsigned int htype, unsigned int post, unsigned int incoming, const gnutls_datum_t *msg) {
	struct command *cmd;
	int gtls_errno = GNUTLS_E_SUCCESS;
	char sni [sizeof (cmd->cmd.pio_data.pioc_starttls.remoteid)]; // static
	size_t snilen = sizeof (sni);
	int snitype;
	char *lid;

tlog (LOG_DAEMON, LOG_INFO, "Invoked %sprocessor for Client Hello, htype=%d, incoming=%d\n",
		post ? "post" : "pre",
		htype,
		incoming);

fprintf (stderr, "DEBUG: Got errno = %d / %s at %d\n", errno, strerror (errno), __LINE__);
errno = 0;
fprintf (stderr, "DEBUG: Got errno = %d / %s at %d\n", errno, strerror (errno), __LINE__);

if (!post) {
	//
	// Setup a number of common references
	cmd = (struct command *) gnutls_session_get_ptr (session);
	if (cmd == NULL) {
		return GNUTLS_E_INVALID_SESSION;
	}

	//
	// Setup server-specific credentials and priority string
	//TODO// get anonpre value here
fprintf (stderr, "DEBUG: Got gtls_errno = %d at %d\n", gtls_errno, __LINE__);
fprintf (stderr, "DEBUG: Got errno = %d / %s at %d\n", errno, strerror (errno), __LINE__);
	E_g2e ("Failed to reconfigure GnuTLS as a server",
		configure_session (cmd,
			session,
			srv_creds, srv_credcount, 
			cmd->anonpre & ANONPRE_SERVER));
fprintf (stderr, "DEBUG: Got gtls_errno = %d at %d\n", gtls_errno, __LINE__);

} else {

	//
	// Setup a number of common references
	cmd = (struct command *) gnutls_session_get_ptr (session);
	if (cmd == NULL) {
		return GNUTLS_E_INVALID_SESSION;
	}
	lid = cmd->cmd.pio_data.pioc_starttls.localid;

	//
	// Setup to ignore/request/require remote identity (from client)
fprintf (stderr, "DEBUG: Got errno = %d / %s at %d\n", errno, strerror (errno), __LINE__);
	if (cmd->cmd.pio_data.pioc_starttls.flags & PIOF_STARTTLS_IGNORE_REMOTEID) {
		// Neither Request nor Require remoteid; ignore it
		;
	} else if (cmd->cmd.pio_data.pioc_starttls.flags & PIOF_STARTTLS_REQUEST_REMOTEID) {
		// Use Request instead of Require for remoteid
		( //RETURNS_VOID// E_g2e ("Failed to request remote identity",
			gnutls_certificate_server_set_request (
				session,
				GNUTLS_CERT_REQUEST));
fprintf (stderr, "DEBUG: Got gtls_errno = %d at %d\n", gtls_errno, __LINE__);
	} else {
		// Require a remoteid from the client (default)
		( //RETURNS_VOID// E_g2e ("Failed to require remote identity (the default)",
			gnutls_certificate_server_set_request (
				session,
				GNUTLS_CERT_REQUIRE));
fprintf (stderr, "DEBUG: Got gtls_errno = %d at %d\n", gtls_errno, __LINE__);
	}

	//
	// Find the client-helloed ServerNameIndication, or the service name
fprintf (stderr, "DEBUG: Got errno = %d / %s at %d\n", errno, strerror (errno), __LINE__);
	sni [0] = '\0';
	if (gnutls_server_name_get (session, sni, &snilen, &snitype, 0) == 0) {
fprintf (stderr, "DEBUG: Got errno = %d / %s at %d\n", errno, strerror (errno), __LINE__);
		switch (snitype) {
		case GNUTLS_NAME_DNS:
			break;
		// Note: In theory, other name types could be sent, and it would
		// be useful to access indexes beyond 0.  In practice, nobody
		// uses other name types than exactly one GNUTLS_NAME_DNS.
		default:
			sni [0] = '\0';
			tlog (TLOG_TLS, LOG_ERR, "Received an unexpected SNI type; that is possible but uncommon; skipping SNI");
fprintf (stderr, "DEBUG: Got errno = %d / %s at %d\n", errno, strerror (errno), __LINE__);
			break;
		}
	}
fprintf (stderr, "DEBUG: Got errno = %d / %s at %d\n", errno, strerror (errno), __LINE__);
	if (sni [0] != '\0') {
		if (*lid != '\0') {
			int atidx;
			for (atidx=128; atidx > 0; atidx--) {
				if (lid [atidx-1] == '@') {
					break;
				}
			}
			if (strncmp (sni, lid + atidx, sizeof (sni)-atidx) != 0) {
				tlog (TLOG_USER | TLOG_TLS, LOG_ERR, "Mismatch between client-sent SNI %s and local identity %s", sni, lid);
fprintf (stderr, "DEBUG: Got errno = %d / %s at %d\n", errno, strerror (errno), __LINE__);
				return GNUTLS_E_UNEXPECTED_HANDSHAKE_PACKET;
			}
		} else {
			memcpy (lid, sni, sizeof (sni));
fprintf (stderr, "DEBUG: Got errno = %d / %s at %d\n", errno, strerror (errno), __LINE__);
		}
	} else {
		memcpy (sni, lid, sizeof (sni)-1);
fprintf (stderr, "DEBUG: Got errno = %d / %s at %d\n", errno, strerror (errno), __LINE__);
		sni [sizeof (sni) - 1] = '\0';
	}
fprintf (stderr, "DEBUG: Got gtls_errno = %d at %d\n", gtls_errno, __LINE__);
}

	//
	// Lap up any unnoticed POSIX error messages
	if (errno != 0) {
		cmd->session_errno = errno;
fprintf (stderr, "DEBUG: Got errno = %d / %s at %d\n", errno, strerror (errno), __LINE__);
		gtls_errno = GNUTLS_E_NO_CIPHER_SUITES;	/* Vaguely matching */
fprintf (stderr, "DEBUG: Got gtls_errno = %d at %d\n", gtls_errno, __LINE__);
	}

	//
	// Round off with an overal judgement
fprintf (stderr, "DEBUG: Returning gtls_errno = %d or \"%s\" from srv_clihello()\n", gtls_errno, gnutls_strerror (gtls_errno));
	return gtls_errno;
}


int cli_srpcreds_retrieve (gnutls_session_t session,
				char **username,
				char **password) {
	//TODO:FIXED//
	tlog (TLOG_CRYPTO, LOG_DEBUG, "Picking up SRP credentials");
	*username = strdup ("tester");
	*password = strdup ("test");
	return GNUTLS_E_SUCCESS;
}


/* Setup credentials to be shared by all clients and servers.
 * Credentials are generally implemented through callback functions.
 * This should be called after setting up DH parameters.
 */
static int setup_starttls_credentials (void) {
	gnutls_anon_server_credentials_t srv_anoncred = NULL;
	gnutls_anon_client_credentials_t cli_anoncred = NULL;
	gnutls_certificate_credentials_t clisrv_certcred = NULL;
	//TODO:NOTHERE// int srpbits;
	gnutls_srp_server_credentials_t srv_srpcred = NULL;
	gnutls_srp_client_credentials_t cli_srpcred = NULL;
	//TODO// gnutls_kdh_server_credentials_t srv_kdhcred = NULL;
	//TODO// gnutls_kdh_server_credentials_t cli_kdhcred = NULL;
	int gtls_errno = GNUTLS_E_SUCCESS;
	int gtls_errno_stack0 = GNUTLS_E_SUCCESS;

	//
	// Construct anonymous server credentials
	E_g2e ("Failed to allocate ANON-DH server credentials",
		gnutls_anon_allocate_server_credentials (
			&srv_anoncred));
	if (!have_error_codes ()) /* E_g2e (...) */ gnutls_anon_set_server_dh_params (
		srv_anoncred,
		dh_params);
	if (gtls_errno == GNUTLS_E_SUCCESS) {
		tlog (TLOG_CRYPTO, LOG_INFO, "Setting server anonymous credentials");
		srv_creds [srv_credcount].credtp = GNUTLS_CRD_ANON;
		srv_creds [srv_credcount].cred   = (void *) srv_anoncred;
		srv_credcount++;
	} else if (srv_anoncred != NULL) {
		gnutls_anon_free_server_credentials (srv_anoncred);
		srv_anoncred = NULL;
	}

	//
	// Construct anonymous client credentials
	gtls_errno = gtls_errno_stack0;	// Don't pop, just forget last failures
	E_g2e ("Failed to allocate ANON-DH client credentials",
		gnutls_anon_allocate_client_credentials (
			&cli_anoncred));
#ifdef MIRROR_IMAGE_OF_SERVER_ANONYMOUS_CREDENTIALS
	// NOTE: This is not done under TLS; server always provides DH params
	if (!have_error_codes ()) gnutls_anon_set_client_dh_params (
		cli_anoncred,
		dh_params);
#endif
	if (gtls_errno == GNUTLS_E_SUCCESS) {
		tlog (TLOG_CRYPTO, LOG_INFO, "Setting client anonymous credentials");
		cli_creds [cli_credcount].credtp = GNUTLS_CRD_ANON;
		cli_creds [cli_credcount].cred   = (void *) cli_anoncred;
		cli_credcount++;
	} else if (cli_anoncred != NULL) {
		gnutls_anon_free_client_credentials (cli_anoncred);
		cli_anoncred = NULL;
	}

	//
	// Construct certificate credentials for X.509 and OpenPGP cli/srv
	gtls_errno = gtls_errno_stack0;	// Don't pop, just forget last failures
	E_g2e ("Failed to allocate certificate credentials",
		gnutls_certificate_allocate_credentials (
			&clisrv_certcred));
	//TODO// What to do here when we add locking on DH params?
	gnutls_certificate_set_dh_params (
		clisrv_certcred,
		dh_params);
	gtls_errno_stack0 = gtls_errno;
	/* TODO: Bad code.  GnuTLS 3.2.1 ignores retrieve_function2 when
	 * checking if it can handle the OpenPGP certificate type in
	 * _gnutls_session_cert_type_supported (gnutls_status.c:175) but
	 * it does see the "1" version field.  It does not callback the
	 * "1" version if "2" is present though.
	 */
	if (!have_error_codes ()) /* TODO:GnuTLSversions E_g2e (...) */ gnutls_certificate_set_retrieve_function (
		clisrv_certcred,
		(void *) exit);
	if (!have_error_codes ()) /* TODO:GnuTLSversions E_g2e (...) */ gnutls_certificate_set_retrieve_function2 (
		clisrv_certcred,
		clisrv_cert_retrieve);
#ifdef HAVE_TLS_KDH
	E_g2e ("Failed to set encoding callback for Kerberos Authenticators",
			gnutls_authenticator_set_encode_function (
					clisrv_certcred,
					cli_kdhsig_encode));
	E_g2e ("Failed to set decoding callback for Kerberos Authenticators",
			gnutls_authenticator_set_decode_function (
					clisrv_certcred,
					srv_kdhsig_decode));
#endif
	if (gtls_errno == GNUTLS_E_SUCCESS) {
		// Setup for certificates
		tlog (TLOG_CERT, LOG_INFO, "Setting client and server certificate credentials");
		cli_creds [cli_credcount].credtp = GNUTLS_CRD_CERTIFICATE;
		cli_creds [cli_credcount].cred   = (void *) clisrv_certcred;
		cli_credcount++;
		srv_creds [srv_credcount].credtp = GNUTLS_CRD_CERTIFICATE;
		srv_creds [srv_credcount].cred   = (void *) clisrv_certcred;
		srv_credcount++;
	} else if (clisrv_certcred != NULL) {
		gnutls_certificate_free_credentials (clisrv_certcred);
		clisrv_certcred = NULL;
	}

	//
	// Construct server credentials for SRP authentication
	gtls_errno = gtls_errno_stack0;	// Don't pop, just forget last failures
	E_g2e ("Failed to allocate SRP server credentials",
		gnutls_srp_allocate_server_credentials (
			&srv_srpcred));
	E_g2e ("Failed to set SRP server credentials",
		gnutls_srp_set_server_credentials_file (
			srv_srpcred,
			"../testdata/tlspool-test-srp.passwd",
			"../testdata/tlspool-test-srp.conf"));
	if (gtls_errno == GNUTLS_E_SUCCESS) {
		tlog (TLOG_CRYPTO, LOG_INFO, "Setting server SRP credentials");
		srv_creds [srv_credcount].credtp = GNUTLS_CRD_SRP;
		srv_creds [srv_credcount].cred   = (void *) srv_srpcred;
		srv_credcount++;
	} else if (srv_srpcred != NULL) {
		gnutls_srp_free_server_credentials (srv_srpcred);
		srv_srpcred = NULL;
	}

	//
	// Construct client credentials for SRP authentication
	gtls_errno = gtls_errno_stack0;	// Don't pop, just forget last failures
	E_g2e ("Failed to allocate SRP client credentials",
		gnutls_srp_allocate_client_credentials (
			&cli_srpcred));
	if (!have_error_codes ()) gnutls_srp_set_client_credentials_function (
		cli_srpcred,
		cli_srpcreds_retrieve);
	if (gtls_errno == GNUTLS_E_SUCCESS) {
		tlog (TLOG_CRYPTO, LOG_INFO, "Setting client SRP credentials");
		cli_creds [cli_credcount].credtp = GNUTLS_CRD_SRP;
		cli_creds [cli_credcount].cred   = (void *) cli_srpcred;
		cli_credcount++;
	} else if (cli_srpcred != NULL) {
		gnutls_srp_free_client_credentials (cli_srpcred);
		cli_srpcred = NULL;
	}

	//
	// Construct server credentials for KDH authentication
	//TODO// gtls_errno = gtls_errno_stack0;	// Don't pop, just forget last failures
	//TODO// E_g2e ("Failed to allocate KDH server credentials",
	//TODO// 	gnutls_kdh_allocate_server_credentials (
	//TODO// 		&srv_kdhcred));
	//TODO// E_g2e ("Failed to set KDH server DH params",
	//TODO// 	gnutls_kdh_set_server_dh_params (
	//TODO// 		srv_kdhcred,
	//TODO// 		dh_params));
	//TODO// if (gtls_errno == GNUTLS_E_SUCCESS) {
	//TODO// 	tlog (TLOG_CRYPTO, LOG_INFO, "Setting server KDH credentials");
	//TODO// 	srv_creds [srv_credcount].credtp = GNUTLS_CRD_KDH;
	//TODO// 	srv_creds [srv_credcount].cred   = (void *) srv_kdhcred;
	//TODO// 	srv_credcount++;
	//TODO// } else if (srv_kdhcred != NULL) {
	//TODO// 	gnutls_kdh_free_server_credentials (srv_kdhcred);
	//TODO// 	srv_kdhcred = NULL;
	//TODO// }

	//
	// Construct client credentials for KDH
	//TODO// gtls_errno = gtls_errno_stack0;	// Don't pop, just forget last failures
	//TODO// E_g2e ("Failed to allocate KDH client credentials",
	//TODO// 	gnutls_kdh_allocate_client_credentials (
	//TODO// 		&cli_kdhcred));
	//TODO// E_g2e ("Failed to set KDH client credentials",
	//TODO//	gnutls_kdh_set_client_credentials_function (
	//TODO// 		cli_kdhcred,
	//TODO// 		cli_kdh_retrieve));
	//TODO// if (gtls_errno == GNUTLS_E_SUCCESS) {
	//TODO// 	tlog (TLOG_CRYPTO, LOG_INFO, "Setting client KDH credentials");
	//TODO// 	cli_creds [cli_credcount].credtp = GNUTLS_CRD_KDH;
	//TODO// 	cli_creds [cli_credcount].cred   = (void *) cli_kdhcred;
	//TODO// 	cli_credcount++;
	//TODO// } else if (cli_kdhcred != NULL) {
	//TODO// 	gnutls_kdh_free_client_credentials (cli_kdhcred);
	//TODO//	cli_kdhcred = NULL;
	//TODO// }

	//
	// Ensure that at least one credential has been set
	// TODO: Look at the counters; but at boot, we can require all okay
	if ((gtls_errno == GNUTLS_E_SUCCESS) &&
			( (cli_credcount != EXPECTED_CLI_CREDCOUNT) ||
			  (srv_credcount != EXPECTED_SRV_CREDCOUNT) ) ) {
		tlog (TLOG_CRYPTO, LOG_ERR, "Not all credential types could be setup (cli %d/%d, srv %d/%d, gtls_errno %d)", cli_credcount, EXPECTED_CLI_CREDCOUNT, srv_credcount, EXPECTED_SRV_CREDCOUNT, gtls_errno);
		E_g2e ("Not all credentials could be setup",
			GNUTLS_E_INSUFFICIENT_CREDENTIALS);
	}

	//
	// Report overall error or success
	return gtls_errno;
}


/* Cleanup all credentials created, just before exiting the daemon.
 */
static void cleanup_starttls_credentials (void) {
	while (srv_credcount-- > 0) {
		struct credinfo *crd = &srv_creds [srv_credcount];
		switch (crd->credtp) {
		case GNUTLS_CRD_CERTIFICATE:
			// Shared with client; skipped in server and removed in client
			// gnutls_certificate_free_credentials (crd->cred);
			break;
		case GNUTLS_CRD_ANON:
			gnutls_anon_free_server_credentials (crd->cred);
			break;
		case GNUTLS_CRD_SRP:
			gnutls_srp_free_server_credentials (crd->cred);
			break;
		//TODO// case GNUTLS_CRD_KDH:
		//TODO// 	gnutls_kdh_free_server_credentials (crd->cred);
		//TODO// 	break;
		}
	}
	while (cli_credcount-- > 0) {
		struct credinfo *crd = &cli_creds [cli_credcount];
		switch (crd->credtp) {
		case GNUTLS_CRD_CERTIFICATE:
			// Shared with client; skipped in server and removed in client
			gnutls_certificate_free_credentials (crd->cred);
			break;
		case GNUTLS_CRD_ANON:
			gnutls_anon_free_client_credentials (crd->cred);
			break;
		case GNUTLS_CRD_SRP:
			gnutls_srp_free_client_credentials (crd->cred);
			break;
		//TODO// case GNUTLS_CRD_KDH:
		//TODO// 	gnutls_kdh_free_client_credentials (crd->cred);
		//TODO// 	break;
		}
	}
}


/*
 * The starttls_thread is a main program for the setup of a TLS connection,
 * either in client mode or server mode.  Note that the distinction between
 * client and server mode is only a TLS concern, but not of interest to the
 * application or the records exchanged.
 *
 * If the STARTTLS operation succeeds, this will be reported back to the
 * application, but the TLS pool will continue to be active in a copycat
 * procedure: encrypting outgoing traffic and decrypting incoming traffic.
 *
 * A new handshake may be initiated with a STARTTLS command with the special
 * flag PIOF_STARTTLS_RENEGOTIATE and the ctlkey set to a previously setup
 * TLS connection.  This command runs in a new thread, that cancels the old
 * one (which it can only do while it is waiting in copycat) and then join
 * that thread (and its data) with the current one.  This is based on the
 * ctlkey, which serves to lookup the old thread's data.  When the
 * connection ends for other reasons than a permitted cancel by another
 * thread, will the thread cleanup its own resources.  In these situations,
 * the new command determines the negotiation parameters, and returns identity
 * information.
 *
 * In addition, the remote side may initiate renegotiation.  This is accepted
 * without further ado (although future versions of the TLS Pool may add a
 * callback mechanism to get it approved).  The renegotiation now runs under
 * the originally supplied negotiation parameters.  In case it needs a new
 * local identity, it may also perform callbacks.  Possibly repeating what
 * happened before -- but most often, a server will start processing a
 * protocol and determine that it requires more for the requested level of
 * service, and then renegotiate.  This is common, for example, with HTTPS
 * connections that decide they need a client certificate for certain URLs.
 * The implementation of this facility is currently as unstructured as the
 * facility itself, namely through a goto.  We may come to the conclusion
 * that a loop is in fact a warranted alternative, but we're not yet
 * convinced that this would match with other "structures" in TLS.
 *
 * In conclusion, there are three possible ways of running this code:
 *  1. For a new connection.  Many variables are not known and build up
 *     in the course of running the function.
 *  2. After a command requesting renegotiation.  This overtakes the prior
 *     connection's thread, and copies its data from the ctlkeynode_tls.
 *     The resulting code has a number of variables filled in already at
 *     an earlier stage.
 *  3. After a remote request for renegotiation.  This loops back to an
 *     earlier phase, but after the thread takeover and ctlkeynode_tls copy
 *     of the explicit command for renegotation.  Its behaviour is subtly
 *     different in that it has no command to act on, and so it cannot
 *     send responses or error codes.  It will however log and shutdown
 *     as the command-driven options would.  It will not perform callbacks
 *     for PIOC_STARTTLS_LOCALID_V2 or PIOC_PLAINTEXT_CONNECT_V2.  It will
 *     however trigger the PIOC_LIDENTRY_CALLBACK_V2 through the separate
 *     callback command, if one is registered.
 * Yeah, it's great fun, coding TLS and keeping it both flexible and secure.
 */
static void *starttls_thread (void *cmd_void) {
	struct command *cmd, *replycmd;
	struct command cmd_copy; // for relooping during renegotiation
	struct pioc_starttls orig_starttls;
	uint32_t orig_cmdcode;
	int plainfd = -1;
	int cryptfd = -1;
	gnutls_session_t session;
	int got_session = 0;
	int gtls_errno = GNUTLS_E_SUCCESS;
	int i;
	struct ctlkeynode_tls *ckn = NULL;
	uint32_t tout;
	int forked = 0;
	int want_remoteid = 1;
	int got_remoteid = 0;
	int renegotiating = 0;
	char *preauth = NULL;
	unsigned int preauthlen = 0;
	int taking_over = 0;
	int my_maxpreauth = 0;
	int anonpost = 0;

	//
	// Block thread cancellation -- and re-enable it in copycat()
	assert (pthread_setcancelstate (PTHREAD_CANCEL_DISABLE, NULL) == 0);

	//
	// General thread setup
	replycmd = cmd = (struct command *) cmd_void;
	if (cmd == NULL) {
		send_error (replycmd, EINVAL, "Command structure not received");
		assert (pthread_detach (pthread_self ()) == 0);
		return NULL;
	}
	*cmd->valflags = '\0';
	cmd->session_errno = 0;
	cmd->anonpre = 0;
	orig_cmdcode = cmd->cmd.pio_cmd;
	memcpy (&orig_starttls, &cmd->cmd.pio_data.pioc_starttls, sizeof (orig_starttls));
	cmd->orig_starttls = &orig_starttls;
	cryptfd = cmd->passfd;
	cmd->passfd = -1;
//TODO:TEST Removed here because it is tested below
/*
	if (cryptfd < 0) {
		tlog (TLOG_UNIXSOCK, LOG_ERR, "No ciphertext file descriptor supplied to TLS Pool");
		send_error (replycmd, EINVAL, "No ciphertext file descriptor supplied to TLS Pool");
		assert (pthread_detach (pthread_self ()) == 0);
		return NULL;
	}
*/
	cmd->session_certificate = (intptr_t) (void *) NULL;
	cmd->session_privatekey  = (intptr_t) (void *) NULL;

	//
	// In case of renegotiation, lookup the previous ctlkeynode by its
	// ctlkey.  The fact that we have ckn != NULL indicates that we are
	// renegotiating in the code below; it will supply information as
	// we continue to run the TLS process.
	if (cmd->cmd.pio_data.pioc_starttls.flags & PIOF_STARTTLS_RENEGOTIATE) {
fprintf (stderr, "DEBUG: Got a request to renegotiate existing TLS connection\n");
		//
		// Check that no FD was passed (and ended up in cryptfd)
		if (cryptfd >= 0) {
			tlog (TLOG_UNIXSOCK, LOG_ERR, "Renegotiation started with extraneous file descriptor");
			send_error (replycmd, EPROTO, "File handle supplied for renegotiation");
			close (cryptfd);
			assert (pthread_detach (pthread_self ()) == 0);
			return NULL;
		}
		//
		// First find the ctlkeynode_tls
		ckn = (struct ctlkeynode_tls *) ctlkey_find (cmd->cmd.pio_data.pioc_starttls.ctlkey, security_tls, cmd->clientfd);
fprintf (stderr, "DEBUG: Got ckn == 0x%0x\n", (intptr_t) ckn);
		if (ckn == NULL) {
			tlog (TLOG_UNIXSOCK, LOG_ERR, "Failed to find TLS connection for renegotiation by its ctlkey");
			send_error (replycmd, ESRCH, "Cannot find TLS connection for renegotiation");
			assert (pthread_detach (pthread_self ()) == 0);
			return NULL;
		}
		//
		// Now cancel the pthread for this process
		errno = pthread_cancel (ckn->owner);
fprintf (stderr, "DEBUG: pthread_cancel returned %d\n", errno);
		if (errno == 0) {
			void *retval;
			errno = pthread_join (ckn->owner, &retval);
fprintf (stderr, "DEBUG: pthread_join returned %d\n", errno);
		}
		if (errno == 0) {
			// We have now synchronised with the cancelled thread
			// Cleanup any _remote data in ckn->session->cmd
			cleanup_any_remote_credentials (
				(struct command *) gnutls_session_get_ptr (
					ckn->session));
		}
		if (errno != 0) {
			tlog (TLOG_UNIXSOCK, LOG_ERR, "Failed to interrupt TLS connection for renegotiation");
			send_error (replycmd, errno, "Cannot interrupt TLS connection for renegotiation");
			ctlkey_unfind (&ckn->regent);
			assert (pthread_detach (pthread_self ()) == 0);
			// Do not free the ckn, as the other thread still runs
			return NULL;
		}
		//
		// We are in control!  Assimilate the TLS connection data.
		renegotiating = 1;
		plainfd = ckn->plainfd;
		cryptfd = ckn->cryptfd;
		session = ckn->session;
		got_session = 1;
		taking_over = 1;
		ctlkey_unfind (&ckn->regent);
	}

	// Then follows the unstructured entry point for the unstructured
	// request to a TLS connection to renegotiate its security parameters.
	// Doing this in any other way than with goto would add a lot of
	// make-belief structure that only existed to make this looping
	// possible.  We'd rather be honest and admit the lack of structure
	// that TLS has in this respect.  Maybe we'll capture it one giant loop
	// at some point, but for now that does not seem to add any relief.
	renegotiate:
fprintf (stderr, "DEBUG: Renegotiating = %d, anonpost = %d, plainfd = %d, cryptfd = %d, flags = 0x%x, session = 0x%x, got_session = %d, lid = \"%s\", rid = \"%s\"\n", renegotiating, anonpost, plainfd, cryptfd, cmd->cmd.pio_data.pioc_starttls.flags, session, got_session, cmd->cmd.pio_data.pioc_starttls.localid, cmd->cmd.pio_data.pioc_starttls.remoteid);

	//
	// If this is server renegotiating, send a request to that end
	//TODO// Only invoke gnutls_rehandshake() on the server
	if (renegotiating && (taking_over || anonpost) && (gtls_errno == GNUTLS_E_SUCCESS)) {
fprintf (stderr, "DEBUG: Invoking gnutls_rehandshake in renegotiation loop\n");
		gtls_errno = gnutls_rehandshake (session);
		if (gtls_errno == GNUTLS_E_INVALID_REQUEST) {
			// Clients should not do this; be forgiving
			gtls_errno = GNUTLS_E_SUCCESS;
fprintf (stderr, "DEBUG: Client-side invocation flagged as wrong; compensated error\n");
		}
	}

	//
	// When renegotiating TLS security, ensure that it is done securely
	if (renegotiating && (gnutls_safe_renegotiation_status (session) == 0)) {
		send_error (replycmd, EPROTO, "Renegotiation requested while secure renegotiation is unavailable on remote");
		if (cryptfd >= 0) {
			close (cryptfd);
			cryptfd = -1;
		}
		if (plainfd >= 0) {
			close (plainfd);
			plainfd = -1;
		}
		if (ckn != NULL) {
			if (ctlkey_unregister (ckn->regent.ctlkey)) {
				free (ckn);
				ckn = NULL;
			}
		}
		assert (pthread_detach (pthread_self ()) == 0);
		return NULL;
	}

	//
	// Potentially decouple the controlling fd (ctlkey is in orig_starttls)
	if (cmd->cmd.pio_data.pioc_starttls.flags & PIOF_STARTTLS_FORK) {
		cmd->cmd.pio_data.pioc_starttls.flags &= ~PIOF_STARTTLS_FORK;
		forked = 1;
	}

	//
	// Setup BDB transactions and reset credential datum fields
	if (!anonpost) {
		memset (&cmd->lids, 0, sizeof (cmd->lids));
		manage_txn_begin (&cmd->txn);
	}

	//
	// Permit cancellation of this thread -- TODO: Cleanup?
//TODO:TEST// Defer setcancelstate until copycat() activity
/*
	errno = pthread_setcancelstate (PTHREAD_CANCEL_ENABLE, NULL);
	if (errno != 0) {
		send_error (replycmd, ESRCH, "STARTTLS handler thread cancellability refused");
		if (cryptfd >= 0) {
			close (cryptfd);
			cryptfd = -1;
		}
		if (plainfd >= 0) {
			close (plainfd);
			plainfd = -1;
		}
		if (ckn != NULL) {
			if (ctlkey_unregister (ckn->regent.ctlkey)) {
				free (ckn);
				ckn = NULL;
			}
		}
		manage_txn_rollback (&cmd->txn);
		assert (pthread_detach (pthread_self ()) == 0);
		return NULL;
	}
*/
	//
	// Check and setup the plaintext file handle
	if (cryptfd < 0) {
		send_error (replycmd, EPROTO, "You must supply a TLS-protected socket");
		if (plainfd >= 0) {
			close (plainfd);
			plainfd = -1;
		}
fprintf (stderr, "ctlkey_unregister under ckn=0x%x at %d\n", ckn, __LINE__);
		if (ckn != NULL) {	/* TODO: CHECK NEEDED? */
			if (ctlkey_unregister (ckn->regent.ctlkey)) {
				free (ckn);
				ckn = NULL;
			}
		}
		manage_txn_rollback (&cmd->txn);
		assert (pthread_detach (pthread_self ()) == 0);
		return NULL;
	}

	//
	// Decide on support for the Anonymous Precursor, based on the
	// service name and its appearance in the anonpre_registry.
	// If the remoteid is not interesting to the client then also
	// support an Anonymous Precursor; we have nothing to loose.
	cmd->anonpre &= ~ANONPRE_EITHER;
	if (renegotiating) {
		; // Indeed, during renegotiation we always disable ANON-DH
	} else if (cmd->cmd.pio_data.pioc_starttls.flags & PIOF_STARTTLS_IGNORE_REMOTEID) {
		cmd->anonpre = ANONPRE_EITHER;
		want_remoteid = 0;
	} else {
		int anonpre_regidx =  anonpre_registry_size      >> 1;
		int anonpre_regjmp = (anonpre_registry_size + 1) >> 1;
		int cmp;
		while (anonpre_regjmp > 0) {
			anonpre_regjmp = anonpre_regjmp >> 1;
			cmp = strncasecmp (anonpre_registry [anonpre_regidx].service,
				cmd->cmd.pio_data.pioc_starttls.service,
				TLSPOOL_SERVICELEN);
fprintf (stderr, "DEBUG: anonpre_determination, comparing [%d] %s to %s, found cmp==%d\n", anonpre_regidx, anonpre_registry [anonpre_regidx].service, cmd->cmd.pio_data.pioc_starttls.service, cmp);
			if (cmp == 0) {
				// anonpre_regent matches
				cmd->anonpre = anonpre_registry [anonpre_regidx].flags;
				break;
			} else if (cmp > 0) {
				// anonpre_regent too high
				anonpre_regidx -= 1 + anonpre_regjmp;
				if (anonpre_regidx < 0) {
					anonpre_regidx = 0;
				}
			} else {
				// anonpre_regent too low
				anonpre_regidx += 1 + anonpre_regjmp;
				if (anonpre_regidx >= anonpre_registry_size) {
					anonpre_regidx = anonpre_registry_size - 1;
				}
			}
		}
	}

	//
	// Setup flags for client and/or server roles (make sure there is one)
	if ((!renegotiating) && ((cmd->cmd.pio_data.pioc_starttls.flags & PIOF_STARTTLS_REMOTEROLE_CLIENT) == 0)) {
		cmd->cmd.pio_data.pioc_starttls.flags &= ~PIOF_STARTTLS_LOCALROLE_SERVER;
	}
	if ((!renegotiating) && ((cmd->cmd.pio_data.pioc_starttls.flags & PIOF_STARTTLS_REMOTEROLE_SERVER) == 0)) {
		cmd->cmd.pio_data.pioc_starttls.flags &= ~PIOF_STARTTLS_LOCALROLE_CLIENT;
	}
	if ((cmd->cmd.pio_data.pioc_starttls.flags & (PIOF_STARTTLS_LOCALROLE_CLIENT | PIOF_STARTTLS_LOCALROLE_SERVER)) == 0) {
		//
		// Neither a TLS client nor a TLS server
		//
		send_error (replycmd, ENOTSUP, "Command not supported");
		close (cryptfd);
		if (plainfd >= 0) {
			close (plainfd);
			plainfd = -1;
		}
fprintf (stderr, "ctlkey_unregister under ckn=0x%x at %d\n", ckn, __LINE__);
		if (ckn != NULL) { /* TODO: CHECK NEEDED? */
			if (ctlkey_unregister (ckn->regent.ctlkey)) {
				free (ckn);
				ckn = NULL;
			}
		}
		manage_txn_rollback (&cmd->txn);
		assert (pthread_detach (pthread_self ()) == 0);
		return NULL;
	}

	//
	// Setup the TLS session.  Also see doc/p2p-tls.*
	//
	// TODO: GnuTLS cannot yet setup p2p connections
	if (ckn != NULL) {
		gnutls_session_set_ptr (
			session,
			cmd);
		//TODO:DONE?// Clear various settings... creds, flags, modes? CLI/SRV?
	} else {
		E_g2e ("Failed to initialise GnuTLS peer session",
			gnutls_init (
				&session,
				(((cmd->cmd.pio_data.pioc_starttls.flags & PIOF_STARTTLS_LOCALROLE_CLIENT)? GNUTLS_CLIENT: 0) |
				 ((cmd->cmd.pio_data.pioc_starttls.flags & PIOF_STARTTLS_LOCALROLE_SERVER)? GNUTLS_SERVER: 0))
				));
		if (gtls_errno == GNUTLS_E_SUCCESS) {
			got_session = 1;
			gnutls_session_set_ptr (
				session,
				cmd);
		}
	}
	cmd->session = session;
	//
	// Setup client-specific behaviour if needed
	if (cmd->cmd.pio_data.pioc_starttls.flags & PIOF_STARTTLS_LOCALROLE_CLIENT) {
if (!renegotiating) {	//TODO:TEST//
		//
		// Setup as a TLS client
		//
		int srpbits;
		//
		// Require a minimum security level for SRP
		srpbits = 3072;
		//TODO:CRASH// if (gtls_errno == GNUTLS_E_SUCCESS) gnutls_srp_set_prime_bits (
			//TODO:CRASH// session,
			//TODO:CRASH// srpbits);
		//
		// Setup as a TLS client
		//
		// Setup for potential sending of SNI
		if ((cmd->cmd.pio_data.pioc_starttls.flags & PIOF_STARTTLS_WITHOUT_SNI) == 0) {
			char *str = cmd->cmd.pio_data.pioc_starttls.remoteid;
			int ofs = 0;
			int len = 0;
			while (str [len] && (len < 128)) {
				if (str [len] == '@') {
					ofs = len + 1;
				}
				len++;
			}
			// If no usable remoteid was setup, ignore it
			if ((len > ofs) && (len < 128)) {
				cmd->cmd.pio_data.pioc_starttls.remoteid [sizeof (cmd->cmd.pio_data.pioc_starttls.remoteid)-1] = '\0';
				tlog (TLOG_TLS, LOG_DEBUG, "Sending ServerNameIndication \"%.*s\"", len - ofs, str + ofs);
				E_g2e ("Client failed to setup SNI",
					gnutls_server_name_set (
						session,
						GNUTLS_NAME_DNS,
						str + ofs,
						len - ofs));
			}
		}
} //TODO:TEST//
		//
		// Setup for client credential installation in this session
		//
		// Setup client-specific credentials and priority string
fprintf (stderr, "DEBUG: Configuring client credentials\n");
		E_g2e ("Failed to configure GnuTLS as a client",
			configure_session (cmd,
				session,
				anonpost? NULL: cli_creds,
				anonpost?    0: cli_credcount, 
				cmd->anonpre & ANONPRE_CLIENT));
	}
	//
	// Setup callback to server-specific behaviour if needed
	if (cmd->cmd.pio_data.pioc_starttls.flags & PIOF_STARTTLS_LOCALROLE_SERVER) {
fprintf (stderr, "DEBUG: Configuring for server credentials callback if %d==0\n", gtls_errno);
if (!renegotiating) {	//TODO:TEST//
		if (gtls_errno == GNUTLS_E_SUCCESS) {
			gnutls_handshake_set_hook_function (
				session,
				GNUTLS_HANDSHAKE_CLIENT_HELLO,
				GNUTLS_HOOK_BOTH,
				srv_clienthello);
		}
} //TODO:TEST//
		//TODO:TEST// configure_session _if_ not setup as a client (too)
		//
		// Setup for server credential installation in this session
		//
		// Setup server-specific credentials and priority string
#if 0
		if (! (cmd->cmd.pio_data.pioc_starttls.flags & PIOF_STARTTLS_LOCALROLE_CLIENT)) {
fprintf (stderr, "DEBUG: Configuring server credentials (because it is not a client)\n");
			E_g2e ("Failed to configure GnuTLS as a server",
				configure_session (cmd,
					session,
					anonpost? NULL: srv_creds,
					anonpost?    0: srv_credcount, 
					cmd->anonpre & ANONPRE_SERVER));
		}
#endif
	}

	//
	// Prefetch local identities that might be used in this session
	if (!anonpost) {
		E_g2e ("Failed to fetch local credentials",
			fetch_local_credentials (cmd));
	}

	//
	// Setup a temporary priority string so handshaking can start
	if ((cmd->cmd.pio_data.pioc_starttls.flags & PIOF_STARTTLS_LOCALROLE_CLIENT) == 0) {
		E_g2e ("Failed to preconfigure server token priority string",
				gnutls_priority_set (
					session,
					priority_normal));
	}

	//
	// Check if past code stored an error code through POSIX
	if (cmd->session_errno) {
		gtls_errno = GNUTLS_E_USER_ERROR;
	}

	//
	// Setup a timeout value as specified in the command, where TLS Pool
	// defines 0 as default and ~0 as infinite (GnuTLS has 0 as infinite).
	tout = cmd->cmd.pio_data.pioc_starttls.timeout;
if (renegotiating) {
; // Do not set timeout
} else
	if (tout == TLSPOOL_TIMEOUT_DEFAULT) {
		gnutls_handshake_set_timeout (session, GNUTLS_DEFAULT_HANDSHAKE_TIMEOUT);
	} else if (tout == TLSPOOL_TIMEOUT_INFINITE) {
		gnutls_handshake_set_timeout (session, 0);
	} else {
		gnutls_handshake_set_timeout (session, tout);
	}

	//
	// Now setup for the GnuTLS handshake
	//
if (renegotiating) {
; // Do not setup cryptfd
} else
	if (gtls_errno == GNUTLS_E_SUCCESS) {
		gnutls_transport_set_int (session, cryptfd);
	}
	if (gtls_errno != GNUTLS_E_SUCCESS) {
		tlog (TLOG_TLS, LOG_ERR, "Failed to prepare for TLS: %s", gnutls_strerror (gtls_errno));
		if (cmd->session_errno) {
			send_error (replycmd, cmd->session_errno, error_getstring ());
		} else {
			send_error (replycmd, EIO, "Failed to prepare for TLS");
		}
		if (got_session) {
fprintf (stderr, "gnutls_deinit (0x%x) at %d\n", session, __LINE__);
			gnutls_deinit (session);
			got_session = 0;
		}
		close (cryptfd);
		if (plainfd >= 0) {
			close (plainfd);
			plainfd = -1;
		}
fprintf (stderr, "ctlkey_unregister under ckn=0x%x at %d\n", ckn, __LINE__);
		if (ckn != NULL) {	/* TODO: CHECK NEEDED? */
			if (ctlkey_unregister (ckn->regent.ctlkey)) {
				free (ckn);
				ckn = NULL;
			}
		}
		manage_txn_rollback (&cmd->txn);
		assert (pthread_detach (pthread_self ()) == 0);
		return NULL;
	}
	tlog (TLOG_UNIXSOCK | TLOG_TLS, LOG_DEBUG, "TLS handshake started over %d", cryptfd);
	do {
		//
		// Take a rehandshaking step forward.
		//
		gtls_errno = gnutls_handshake (session);
		//
		// When data is sent before completing
		// the rehandshake, then it's something
		// harmless, given the criteria for the
		// anonpre_registry.  We pass it on and
		// don't worry about it.  We do report
		// it though!
		//
		// Note: Applications should be willing
		// to buffer or process such early data
		// before the handshake is over or else
		// the handshake will bail out in error.
		//
		if (gtls_errno == GNUTLS_E_GOT_APPLICATION_DATA) {
			if (my_maxpreauth <= 0) {
				tlog (TLOG_COPYCAT, LOG_ERR, "Received unwanted early data before authentication is complete");
				break; // Terminate the handshake
			} else if (preauth == NULL) {
				preauth = malloc (my_maxpreauth);
				if (preauth == NULL) {
					gtls_errno = GNUTLS_E_MEMORY_ERROR;
					break; // Terminate the handshake
				}
			}
		}
		if (gtls_errno == GNUTLS_E_GOT_APPLICATION_DATA) {
			if (preauthlen >= my_maxpreauth) {
				tlog (TLOG_COPYCAT, LOG_ERR, "Received more early data than willing to receive (%d bytes)", my_maxpreauth);
				break; // Terminate the handshake
			}
		}
		if (gtls_errno == GNUTLS_E_GOT_APPLICATION_DATA) {
			ssize_t sz;
			sz = gnutls_record_recv (session, preauth + preauthlen, my_maxpreauth - preauthlen);
			tlog (TLOG_COPYCAT, LOG_DEBUG, "Received %d remote bytes (or error if <0) from %d during anonymous precursor\n", (int) sz, cryptfd);
			if (sz > 0) {
				preauthlen += sz;
				gtls_errno = GNUTLS_E_SUCCESS;
			} else {
				gtls_errno = sz; // It's actually an error code
			}
		}
	} while ((gtls_errno < 0) &&
		//DROPPED// (gtls_errno != GNUTLS_E_GOT_APPLICATION_DATA) &&
		//DROPPED// (gtls_errno != GNUTLS_E_WARNING_ALERT_RECEIVED) &&
		(gnutls_error_is_fatal (gtls_errno) == 0));
	//
	// Handshake done -- initialise remote_xxx, vfystatus, got_remoteid
	if ((gtls_errno == 0) && !(cmd->cmd.pio_data.pioc_starttls.flags & PIOF_STARTTLS_IGNORE_REMOTEID)) {
		// We want to try to authenticate the peer
		E_g2e ("Failed to retrieve peer credentials",
				fetch_remote_credentials (cmd));
		if (gtls_errno == GNUTLS_E_AUTH_ERROR) {
			if (cmd->cmd.pio_data.pioc_starttls.flags & PIOF_STARTTLS_REQUEST_REMOTEID) {
				// We do not _require_ authentication of the peer
				gtls_errno = 0;
			}
		}
	}
	if (gtls_errno == 0) {
		const gnutls_datum_t *certs;
		unsigned int num_certs;
		got_remoteid = 0;
		switch (cmd->remote_auth_type) { // Peer's cred type
		case GNUTLS_CRD_CERTIFICATE:
			if (cmd->remote_cert_count >= 1) {
				got_remoteid = 1;
			}
#ifdef PHASED_OUT_DIRECT_VALIDATION
			E_g2e ("Failed to validate peer",
				gnutls_certificate_verify_peers2 (
					session,
					&cmd->vfystatus));
#endif
			cmd->vfystatus = 0;
			break;
		case GNUTLS_CRD_PSK:
			// Difficult... what did the history say about this?
			got_remoteid = 0;
			cmd->vfystatus = GNUTLS_CERT_SIGNER_NOT_FOUND;
			break;
		case GNUTLS_CRD_SRP:
			// Got a credential, validation follows later on
			//TODO// SRP does not really auth the server
			got_remoteid = 1;
			cmd->vfystatus = GNUTLS_CERT_SIGNER_NOT_FOUND;
			break;
		case GNUTLS_CRD_ANON:
			// Did not get a credential, perhaps due to anonpre
			got_remoteid = 0;
			cmd->vfystatus = GNUTLS_CERT_INVALID | GNUTLS_CERT_SIGNER_NOT_FOUND | GNUTLS_CERT_SIGNATURE_FAILURE;
			break;
		case GNUTLS_CRD_IA:
			// Inner Application extension is no true credential
			// Should we compare the client-requested service?
			// Should we renegotiate into the ALPN protocol?
			got_remoteid = 0;
			cmd->vfystatus = GNUTLS_CERT_INVALID | GNUTLS_CERT_SIGNER_NOT_FOUND | GNUTLS_CERT_SIGNATURE_FAILURE;
			break;
		default:
			// Unknown creds cautiously considered unauthentitcated
			got_remoteid = 0;
			cmd->vfystatus = ~ (unsigned short) 0;	// It's all bad
			break;
		}
		//
		// Now recognise and handle the Anonymous Precursor
		if (((cmd->anonpre & ANONPRE_EITHER) != 0)
					&& want_remoteid && !got_remoteid) {
			assert (anonpost == 0);
			valexp_valflag_set (cmd, 'A');
			// Disable ANON-protocols but keep creds from before
			//TODO:ELSEWHERE// tlog (TLOG_TLS, LOG_DEBUG, "Reconfiguring TLS over %d without Anonymous Precursor\n", cryptfd);
			//TODO:ELSEWHERE// E_g2e ("Failed to reconfigure GnuTLS without anonymous precursor",
				//TODO:ELSEWHERE// configure_session (cmd,
					//TODO:ELSEWHERE// session,
					//TODO:ELSEWHERE// NULL, 0, 
					//TODO:ELSEWHERE// 0));
			// We do not want to use ANON-DH if the flag
			// ANONPRE_EXTEND_MASTER_SECRET is set for the protocol
			// but the remote peer does not support it.  Only if
			// this problem cannot possibly occur, permit
			// my_maxpreauth > 0 for early data acceptance.
			my_maxpreauth = 0;
			if (cmd->anonpre & ANONPRE_EXTEND_MASTER_SECRET) {
#if GNUTLS_VERSION_NUMBER >= 0x030400
				gnutls_ext_priv_data_t ext;
				if (!gnutls_ext_get_data (session, 23, &ext)) {
					my_maxpreauth = maxpreauth;
				}
#endif
			} else {
				my_maxpreauth = maxpreauth;
			}
			if (gtls_errno == 0) {
				tlog (TLOG_UNIXSOCK | TLOG_TLS, LOG_DEBUG, "TLS handshake continued over %d after anonymous precursor", cryptfd);
				renegotiating = 1; // (de)selects steps
				anonpost = 1;      // (de)selects steps
				goto renegotiate;
			}
		}
	}
	if ((gtls_errno == GNUTLS_E_SUCCESS) && cmd->session_errno) {
		gtls_errno = GNUTLS_E_USER_ERROR;
	}
	taking_over = 0;

	//
	// Run the validation expression logic, using expressions we ran into
fprintf (stderr, "DEBUG: Prior to valexp, gtls_errno = %d\n", gtls_errno);
	if (gtls_errno == GNUTLS_E_SUCCESS) {
		struct valexp *verun = NULL;
		char *valexp_conj [3];
		int valexp_conj_count = 0;
		// Setup for validation expression runthrough
		cmd->valexp_result = -1;
		if ((cmd->trust_valexp != NULL) && (0 != strcmp (cmd->trust_valexp, "1"))) {
fprintf (stderr, "DEBUG: Trust valexp \"%s\" @ 0x%016x\n", cmd->trust_valexp, (uint64_t) cmd->trust_valexp);
			valexp_conj [valexp_conj_count++] = cmd->trust_valexp;
		}
		if (cmd->lids [LID_TYPE_VALEXP - LID_TYPE_MIN].data != NULL) {
			// Interpret the entry, abuse p11uri as valexp
			int ok;
			uint32_t flags;
			char *lid_valexp;
			gnutls_datum_t ignored;
			ok = dbcred_interpret (
				&cmd->lids [LID_TYPE_VALEXP - LID_TYPE_MIN],
				&flags,
				&lid_valexp,
				&ignored.data,
				&ignored.size);
fprintf (stderr, "DEBUG: LocalID valexp \"%s\" @ 0x%016x (ok=%d)\n", lid_valexp, (uint64_t) lid_valexp, ok);
			if (ok && (lid_valexp != NULL)) {
				valexp_conj [valexp_conj_count++] = lid_valexp;
			} else {
				gtls_errno = GNUTLS_E_AUTH_ERROR;
			}
		}
fprintf (stderr, "DEBUG: Number of valexp is %d, gtls_errno=%d\n", valexp_conj_count, gtls_errno);
		// Optionally start computing the validation expression
		if ((gtls_errno == GNUTLS_E_SUCCESS) && (valexp_conj_count > 0)) {
			valexp_conj [valexp_conj_count] = NULL;
			verun = valexp_register (
				valexp_conj,
				have_starttls_validation (),
				(void *) cmd);
fprintf (stderr, "DEBUG: Registered to verun = 0x%016x\n", (uint64_t) verun);
			if (verun == NULL) {
				gtls_errno = GNUTLS_E_AUTH_ERROR;
			}
		}
		// When setup, run the validation expressions to completion
		if (verun != NULL) {
			while (cmd->valexp_result == -1) {
				; //TODO: Tickle async predicate run completion
			}
fprintf (stderr, "DEBUG: Finishing tickling \"async\" predicates for valexp\n");
			if (cmd->valexp_result != 1) {
				tlog (TLOG_TLS, LOG_INFO, "TLS validation expression result is %d", cmd->valexp_result);
				gtls_errno = GNUTLS_E_AUTH_ERROR;
fprintf (stderr, "DEBUG: valexp returns NEGATIVE result\n");
			}
else fprintf (stderr, "DEBUG: valexp returns POSITIVE result\n");
			valexp_unregister (verun);
fprintf (stderr, "DEBUG: Unregistered verun 0x%016x\n", (uint64_t) verun);
		}
	}

	//
	// Cleanup any prefetched identities
	for (i=LID_TYPE_MIN; i<=LID_TYPE_MAX; i++) {
		if (cmd->lids [i - LID_TYPE_MIN].data != NULL) {
fprintf (stderr, "DEBUG: Freeing cmd->lids[%d].data 0x%016x\n", i-LID_TYPE_MIN, cmd->lids [i-LID_TYPE_MIN].data);
			free (cmd->lids [i - LID_TYPE_MIN].data);
		}
	}
	memset (cmd->lids, 0, sizeof (cmd->lids));
	//
	// Cleanup any trust_valexp duplicate string
	if (cmd->trust_valexp != NULL) {
		free (cmd->trust_valexp);
		cmd->trust_valexp = NULL;
	}
	//
	// Cleanup any Kerberos session key -- it served its purpose
	if (cmd->krb_key.contents != NULL) {
		// RATHER BLUNT: It shouldn't matter which krbctx_ is used...
		krb5_free_keyblock_contents (krbctx_srv, &cmd->krb_key);
		memset (&cmd->krb_key, 0, sizeof (cmd->krb_key));
	}
	if (cmd->krbid_srv != NULL) {
		// RATHER BLUNT: It shouldn't matter which krbctx_ is used...
		krb5_free_principal (krbctx_srv, cmd->krbid_srv);
		cmd->krbid_srv = NULL;
	}
	if (cmd->krbid_cli != NULL) {
		// RATHER BLUNT: It shouldn't matter which krbctx_ is used...
		krb5_free_principal (krbctx_srv, cmd->krbid_cli);
		cmd->krbid_cli = NULL;
	}

#if 0
/* This is not proper.  gnutls_certificate_set_key() suggests that these are
 * automatically cleaned up, and although this is not repeated in
 * gnutls_certificate_set_retrieve_function2() it is likely to be related.
 * Plus, renegotiation with this code in place bogged down on failed pcerts;
 * they were detected in _gnutls_selected_cert_supported_kx() but their
 * key exchange algorithm was never found.
 */
	if (NULL != (void *) cmd->session_privatekey) {
		gnutls_privkey_deinit ((void *) cmd->session_privatekey);
		cmd->session_privatekey = (intptr_t) (void *) NULL;
	}
	if (NULL != (void *) cmd->session_certificate) {
		gnutls_pcert_deinit ((void *) cmd->session_certificate);
		free ((void *) cmd->session_certificate);
		cmd->session_certificate = (intptr_t) (void *) NULL;
	}
#endif

	//
	// From here, assume nothing about the cmd->cmd structure; as part of
	// the handshake, it may have passed through the client's control, as
	// part of a callback.  So, reinitialise the entire return structure.
	//TODO// Or backup the (struct pioc_starttls) before handshaking
	cmd->cmd.pio_cmd = orig_cmdcode;
	cmd->cmd.pio_data.pioc_starttls.localid  [0] =
	cmd->cmd.pio_data.pioc_starttls.remoteid [0] = '\0';

	//
	// Respond to positive or negative outcome of the handshake
	if (gtls_errno != GNUTLS_E_SUCCESS) {
		tlog (TLOG_TLS, LOG_ERR, "TLS handshake failed: %s", gnutls_strerror (gtls_errno));
		if (cmd->session_errno) {
			char *errstr;
			tlog (TLOG_TLS, LOG_ERR, "Underlying cause may be: %s", strerror (cmd->session_errno));
			errstr = error_getstring ();
			if (errstr == NULL) {
				errstr = "TLS handshake failed";
			}
			send_error (replycmd, cmd->session_errno, errstr);
		} else {
			send_error (replycmd, EPERM, "TLS handshake failed");
		}
		if (preauth) {
			free (preauth);
		}
		if (got_session) {
fprintf (stderr, "gnutls_deinit (0x%x) at %d\n", session, __LINE__);
			gnutls_deinit (session);
			got_session = 0;
		}
		close (cryptfd);
		if (plainfd >= 0) {
			close (plainfd);
			plainfd = -1;
		}
fprintf (stderr, "ctlkey_unregister under ckn=0x%x at %d\n", ckn, __LINE__);
		if (ckn != NULL) {	/* TODO: CHECK NEEDED? */
			if (ctlkey_unregister (ckn->regent.ctlkey)) {
				free (ckn);
				ckn = NULL;
			}
		}
		manage_txn_rollback (&cmd->txn);
		assert (pthread_detach (pthread_self ()) == 0);
		return NULL;
        } else {
		tlog (TLOG_UNIXSOCK | TLOG_TLS, LOG_INFO, "TLS handshake succeeded over %d", cryptfd);
		//TODO// extract_authenticated_remote_identity (cmd);
	}

	//
	// Request the plaintext file descriptor with a callback
	if (plainfd < 0) {
		uint32_t oldcmd = cmd->cmd.pio_cmd;
		struct command *resp;
		cmd->cmd.pio_cmd = PIOC_PLAINTEXT_CONNECT_V2;
		tlog (TLOG_UNIXSOCK, LOG_DEBUG, "Calling send_callback_and_await_response with PIOC_PLAINTEXT_CONNECT_V2");
		resp = send_callback_and_await_response (replycmd, 0);
		assert (resp != NULL);	// No timeout, should be non-NULL
		if (resp->cmd.pio_cmd != PIOC_PLAINTEXT_CONNECT_V2) {
			tlog (TLOG_UNIXSOCK, LOG_ERR, "Callback response has unexpected command code");
			send_error (replycmd, EINVAL, "Callback response has bad command code");
			if (preauth) {
				free (preauth);
			}
			if (got_session) {
fprintf (stderr, "gnutls_deinit (0x%x) at %d\n", session, __LINE__);
				gnutls_deinit (session);
				got_session = 0;
			}
			close (cryptfd);
fprintf (stderr, "ctlkey_unregister under ckn=0x%x at %d\n", ckn, __LINE__);
			if (ckn) {	/* TODO: CHECK NEEDED? PRACTICE=>YES */
				if (ctlkey_unregister (ckn->regent.ctlkey)) {
					free (ckn);
					ckn = NULL;
				}
			}
			manage_txn_rollback (&cmd->txn);
			assert (pthread_detach (pthread_self ()) == 0);
			return NULL;
		}
		cmd->cmd.pio_cmd = oldcmd;
		tlog (TLOG_UNIXSOCK, LOG_DEBUG, "Processing callback response that set plainfd:=%d for lid==\"%s\" and rid==\"%s\"", cmd->passfd, cmd->cmd.pio_data.pioc_starttls.localid, cmd->cmd.pio_data.pioc_starttls.remoteid);
		plainfd = resp->passfd;
		resp->passfd = -1;
	}
	if (plainfd < 0) {
		tlog (TLOG_UNIXSOCK, LOG_ERR, "No plaintext file descriptor supplied to TLS Pool");
		send_error (replycmd, EINVAL, "No plaintext file descriptor supplied to TLS Pool");
		if (preauth) {
			free (preauth);
		}
		if (got_session) {
fprintf (stderr, "gnutls_deinit (0x%x) at %d\n", session, __LINE__);
			gnutls_deinit (session);
			got_session = 0;
		}
		close (cryptfd);
fprintf (stderr, "ctlkey_unregister under ckn=0x%x at %d\n", ckn, __LINE__);
		if (ckn != NULL) {	/* TODO: CHECK NEEDED? */
			if (ctlkey_unregister (ckn->regent.ctlkey)) {
				free (ckn);
				ckn = NULL;
			}
		}
		manage_txn_rollback (&cmd->txn);
		assert (pthread_detach (pthread_self ()) == 0);
		return NULL;
	}
	//DEFERRED// send_command (replycmd, -1);		// app sent plainfd to us

	//
	// Copy TLS records until the connection is closed
	manage_txn_commit (&cmd->txn);
	if (!renegotiating) {
		ckn = (struct ctlkeynode_tls *) malloc (sizeof (struct ctlkeynode_tls));
	}
	if (ckn == NULL) {
		send_error (replycmd, ENOMEM, "Out of memory allocating control key structure");
	} else {
		int detach = (orig_starttls.flags & PIOF_STARTTLS_DETACH) != 0;
		ckn->session = session;
		ckn->owner = pthread_self ();
		ckn->cryptfd = cryptfd;
		ckn->plainfd = plainfd;
//DEBUG// fprintf (stderr, "Registering control key\n");
		if (renegotiating || (ctlkey_register (orig_starttls.ctlkey, &ckn->regent, security_tls, detach ? INVALID_POOL_HANDLE : cmd->clientfd, forked) == 0)) {
			int copied = GNUTLS_E_SUCCESS;
			send_command (replycmd, -1);		// app sent plainfd to us
			if (preauth) {

				//
				// Check on extended master secret if desired
				if (cmd->anonpre & ANONPRE_EXTEND_MASTER_SECRET) {
#if GNUTLS_VERSION_NUMBER >= 0x030400
					gnutls_ext_priv_data_t ext;
					if (!gnutls_ext_get_data (session, 23, &ext)) {
						cmd->anonpre &= ~ANONPRE_EXTEND_MASTER_SECRET;
					}
#endif
				}
				if (cmd->anonpre & ANONPRE_EXTEND_MASTER_SECRET) {
					tlog (TLOG_COPYCAT, LOG_ERR, "Received %d remote bytes from anonymous precursor but lacking %s-required authentication through extended master secret", orig_starttls.service);
					gtls_errno = GNUTLS_E_LARGE_PACKET;
					copied = 0;

				} else if (write (plainfd, preauth, preauthlen) == preauthlen) {
					tlog (TLOG_COPYCAT, LOG_DEBUG, "Passed on %d remote bytes from anonymous precursor to %d\n", preauthlen, plainfd);
					free (preauth);
					preauth = NULL;
					copied = copycat (plainfd, cryptfd, session, detach ? INVALID_POOL_HANDLE : cmd->clientfd);
				} else {
					tlog (TLOG_COPYCAT, LOG_DEBUG, "Failed to pass on %d remote bytes from anonymous precursor to %d\n", preauthlen, plainfd);
				}
			} else {
				copied = copycat (plainfd, cryptfd, session, detach ? INVALID_POOL_HANDLE : cmd->clientfd);
			}
			// Renegotiate if copycat asked us to
			if (copied == GNUTLS_E_REHANDSHAKE) {
				// Yes, goto is a dirty technique.  On the
				// other hand, so is forcing unstructured
				// code flows into a make-belief structure
				// that needs changing over and over again.
				// I fear goto is the most reasonable way
				// of handling this rather obtuse structure
				// of renegotiation of security in TLS :(
				//TODO// Ensure secure renegotiation!!!
				renegotiating = 1;
				replycmd = NULL; // Bypass all send_XXX()
				memcpy (&cmd_copy, cmd, sizeof (cmd_copy));
				cmd = &cmd_copy;
				memcpy (cmd->cmd.pio_data.pioc_starttls.localid, orig_starttls.localid, sizeof (cmd->cmd.pio_data.pioc_starttls.localid));
				memcpy (cmd->cmd.pio_data.pioc_starttls.remoteid, orig_starttls.remoteid, sizeof (cmd->cmd.pio_data.pioc_starttls.remoteid));
				cmd->cmd.pio_data.pioc_starttls.flags = orig_starttls.flags & ~PIOF_STARTTLS_LOCALID_CHECK;
				// Disabling the flag causing LOCALID_CHECK
				// ...and plainfd >= 0 so no PLAINTEXT_CONNECT
				// ...so there will be no callbacks to cmd
fprintf (stderr, "DEBUG: Goto renegotiate with cmd.lid = \"%s\" and orig_cmd.lid = \"%s\" and cmd.rid = \"%s\" and orig_cmd.rid = \"%s\" and cmd.flags = 0x%x and orig_cmd.flags = 0x%x\n", cmd->cmd.pio_data.pioc_starttls.localid, orig_starttls.localid, cmd->cmd.pio_data.pioc_starttls.remoteid, orig_starttls.remoteid, cmd->cmd.pio_data.pioc_starttls.flags, orig_starttls.flags);
				goto renegotiate;
			}
//DEBUG// fprintf (stderr, "Unregistering control key\n");
			// Unregister by ctlkey, which should always succeed
			// if the TLS connection hadn't been closed down yet;
			// and if it does, the memory can be freed.  Note that
			// the ctlkey is not taken from the ckn, which may
			// already have been freed if the ctlfd was closed
			// and the connection could not continue detached
			// (such as after forking it).
fprintf (stderr, "ctlkey_unregister under ckn=0x%x at %d\n", ckn, __LINE__);
			if (ctlkey_unregister (orig_starttls.ctlkey)) {
				free (ckn);
			}
			ckn = NULL;
//DEBUG// fprintf (stderr, "Unregistered  control key\n");
		} else {
			send_error (replycmd, ENOENT, "Failed to register control key for TLS connection");
		}
	}
	if (preauth) {
		free (preauth);
		preauth = NULL;
	}
	close (plainfd);
	close (cryptfd);
	cleanup_any_remote_credentials (cmd);
	if (got_session) {
fprintf (stderr, "gnutls_deinit (0x%x) at %d\n", session, __LINE__);
		gnutls_deinit (session);
		got_session = 0;
	}
	assert (pthread_detach (pthread_self ()) == 0);
	return NULL;
}


/*
 * The starttls function responds to an application's request to 
 * setup TLS for a given file descriptor, and return a file descriptor
 * with the unencrypted view when done.  The main thing done here is to
 * spark off a new thread that handles the operations.
 */
void starttls (struct command *cmd) {
	/* Create a thread and, if successful, wait for it to unlock cmd */
	errno = pthread_create (&cmd->handler, NULL, starttls_thread, (void *) cmd);
	if (errno != 0) {
		send_error (cmd, ESRCH, "STARTTLS thread refused");
		return;
	}
//TODO:TEST// Thread detaches itself before terminating w/o followup
/*
	errno = pthread_detach (cmd->handler);
	if (errno != 0) {
		pthread_cancel (cmd->handler);
		send_error (cmd, ESRCH, "STARTTLS thread detachment refused");
		return;
	}
*/
}


/*
 * Run the PRNG for a TLS connection, identified by its control key.  If the connection
 * is not a TLS connection, or if the control key is not found, reply with ERROR;
 * otherwise, the session should help to create pseudo-random bytes.
 */
void starttls_prng (struct command *cmd) {
	uint8_t in1 [TLSPOOL_PRNGBUFLEN];
	uint8_t in2 [TLSPOOL_PRNGBUFLEN];
	int16_t in1len, in2len, prnglen;
	struct ctlkeynode_tls *ckn = NULL;
	char **prefixes;
	int err = 0;
	int gtls_errno = GNUTLS_E_SUCCESS;
	struct pioc_prng *prng = &cmd->cmd.pio_data.pioc_prng;
	//
	// Find arguments and validate them
	in1len  = prng->in1_len;
	in2len  = prng->in2_len;
	prnglen = prng->prng_len;
	err = err || (in1len <= 0);
	err = err || (prnglen > TLSPOOL_PRNGBUFLEN);
	err = err || ((TLSPOOL_CTLKEYLEN + in1len + (in2len >= 0? in2len: 0))
				> TLSPOOL_PRNGBUFLEN);
	if (!err) {
		memcpy (in1, prng->buffer + TLSPOOL_CTLKEYLEN         , in1len);
		if (in2len > 0) {
			memcpy (in2, prng->buffer + TLSPOOL_CTLKEYLEN + in1len, in2len);
		}
	}
	//  - check the label string
	prefixes = tlsprng_label_prefixes;
	while ((!err) && (*prefixes)) {
		char *pf = *prefixes++;
		if (strlen (pf) != in1len) {
			continue;
		}
		if (strcmp (pf, in1) != 0) {
			continue;
		}
	}
	if (*prefixes == NULL) {
		// RFC 5705 defines a private-use prefix "EXPERIMENTAL"
		if ((in1len <= 12) || (strncmp (in1, "EXPERIMENTAL", 12) != 0)) {
			err = 1;
		}
	}
	//  - check the ctlkey (and ensure it is for TLS)
	if (!err) {
//DEBUG// fprintf (stderr, "Hoping to find control key\n");
		ckn = (struct ctlkeynode_tls *) ctlkey_find (prng->buffer, security_tls, cmd->clientfd);
	}
	//
	// Now wipe the PRNG buffer to get rid of any sensitive bytes
	memset (prng->buffer, 0, TLSPOOL_PRNGBUFLEN);
	//
	// If an error occurrend with the command, report it now
	if (err) {
		send_error (cmd, EINVAL, "TLS PRNG request invalid");
		// ckn is NULL if err != 0, so no need for ctlkey_unfind()
		return;
	}
	if (ckn == NULL) {
		send_error (cmd, ENOENT, "Invalid control key");
		return;
	}
	//
	// Now actually invoke the PRNG command in the GnuTLS backend
	errno = 0;
	E_g2e ("GnuTLS PRNG based on session master key failed",
		gnutls_prf_rfc5705 (ckn->session,
			in1len, in1,
			(in2len >= 0)? in2len: 0, (in2len >= 0) ? in2: NULL,
			prnglen, prng->buffer));
	err = err || (errno != 0);
	//
	// Wipe temporary data / buffers for security reasons
	memset (in1, 0, sizeof (in1));
	memset (in2, 0, sizeof (in2));
	ctlkey_unfind ((struct ctlkeynode *) ckn);
	//
	// Return the outcome to the user
	if (err) {
		send_error (cmd, errno? errno: EIO, "PRNG in TLS backend failed");
	} else {
		send_command (cmd, -1);
	}
}


/* Flying signer functionality.  Create an on-the-fly certificate because
 * the lidentry daemon and/or application asks for this to represent the
 * local identity.  Note that this will only work if the remote party
 * accepts the root identity under which on-the-signing is done.
 *
 * When no root credentials have been configured, this function will
 * fail with GNUTLS_E_AGAIN; it may be used as a hint to try through
 * other (more conventional) means to obtain a client certificate.
 *
 * The API of this function matches that of fetch_local_credentials()
 * and that is not a coincidence; this is a drop-in replacement in some
 * cases.
 *
 * Limitations: The current implementation only supports X.509 certificates
 * to be generated on the fly.  So, this will set LID_TYPE_X509, if anything.
 */
gtls_error certificate_onthefly (struct command *cmd) {
	gtls_error gtls_errno = GNUTLS_E_SUCCESS;
	gnutls_x509_crt_t otfcert;
	time_t now;
	gnutls_x509_subject_alt_name_t altnmtp;
	int i;

	//
	// Sanity checks
	if ((onthefly_issuercrt == NULL) || (onthefly_issuerkey == NULL) || (onthefly_subjectkey == NULL)) {
		// Not able to supply on-the-fly certificates; try someway else
		return GNUTLS_E_AGAIN;
	}
	if (cmd->cmd.pio_data.pioc_starttls.localid [0] == '\0') {
		return GNUTLS_E_NO_CERTIFICATE_FOUND;
	}
	if (cmd->lids [LID_TYPE_X509 - LID_TYPE_MIN].data != NULL) {
		free (cmd->lids [LID_TYPE_X509 - LID_TYPE_MIN].data);
		cmd->lids [LID_TYPE_X509 - LID_TYPE_MIN].data = NULL;
		cmd->lids [LID_TYPE_X509 - LID_TYPE_MIN].size = 0;
	}
	
	//
	// Create an empty certificate
	E_g2e ("Failed to initialise on-the-fly certificate",
		gnutls_x509_crt_init (&otfcert));
	if (gtls_errno != GNUTLS_E_SUCCESS) {
		return gtls_errno;
	}

	//
	// Fill the certificate with the usual field
	E_g2e ("Failed to set on-the-fly certificate to non-CA mode",
		gnutls_x509_crt_set_ca_status (otfcert, 0));
	E_g2e ("Failed to set on-the-fly certificate version",
		gnutls_x509_crt_set_version (otfcert, 3));
	onthefly_serial++;	//TODO// Consider a random byte string
	E_g2e ("Failed to set on-the-fly serial number",
		gnutls_x509_crt_set_serial (otfcert, &onthefly_serial, sizeof (onthefly_serial)));
	// Skip gnutls_x509_crt_set_issuer_by_dn_by_oid(), added when signing
	time (&now);
	E_g2e ("Failed to set on-the-fly activation time to now - 2 min",
		gnutls_x509_crt_set_activation_time (otfcert, now - 120));
	E_g2e ("Failed to set on-the-fly expiration time to now + 3 min",
		gnutls_x509_crt_set_expiration_time (otfcert, now + 180));
	E_g2e ("Setup certificate CN with local identity",
		gnutls_x509_crt_set_dn_by_oid (otfcert, GNUTLS_OID_X520_COMMON_NAME, 0, cmd->cmd.pio_data.pioc_starttls.localid, strnlen (cmd->cmd.pio_data.pioc_starttls.localid, sizeof (cmd->cmd.pio_data.pioc_starttls.localid)-1))); /* TODO: Consider pioc_lidentry as well? */
	E_g2e ("Setup certificate OU with TLS Pool on-the-fly",
		gnutls_x509_crt_set_dn_by_oid (otfcert, GNUTLS_OID_X520_ORGANIZATIONAL_UNIT_NAME, 0, "TLS Pool on-the-fly", 19));
	if (strchr (cmd->cmd.pio_data.pioc_starttls.localid, '@')) {
		// localid has the format of an emailAddress
		altnmtp = GNUTLS_SAN_RFC822NAME;
	} else {
		// localid has the format of a dnsName
		altnmtp = GNUTLS_SAN_DNSNAME;
	}
	E_g2e ("Failed to set subjectAltName to localid",
		gnutls_x509_crt_set_subject_alt_name (otfcert, altnmtp, &cmd->cmd.pio_data.pioc_starttls.localid, strnlen (cmd->cmd.pio_data.pioc_starttls.localid, sizeof (cmd->cmd.pio_data.pioc_starttls.localid) - 1), GNUTLS_FSAN_APPEND));
	//TODO:SKIP, hoping that signing adds: gnutls_x509_crt_set_authority_key_id()
	//TODO:SKIP, hoping that a cert without also works: gnutls_x509_crt_set_subjectkey_id()
	//TODO:SKIP? gnutls_x509_crt_set_extension_by_oid
	//TODO:      gnutls_x509_crt_set_key_usage
	//TODO:SKIP? gnutls_x509_crt_set_ca_status
	for (i=0; i < svcusage_registry_size; i++) {
		if (strcmp (svcusage_registry [i].service, cmd->cmd.pio_data.pioc_starttls.service) == 0) {
			const char **walker;
			E_g2e ("Failed to setup basic key usage during on-the-fly certificate creation",
				gnutls_x509_crt_set_key_usage (otfcert, svcusage_registry [i].usage));
			walker = svcusage_registry [i].oids_non_critical;
			if (walker) {
				while (*walker) {
					E_g2e ("Failed to append non-critical extended key purpose during on-the-fly certificate creation",
						gnutls_x509_crt_set_key_purpose_oid (otfcert, *walker, 0));
					walker++;
				}
			}
			walker = svcusage_registry [i].oids_critical;
			if (walker) {
				while (*walker) {
					E_g2e ("Failed to append critical extended key purpose during on-the-fly certificate creation",
						gnutls_x509_crt_set_key_purpose_oid (otfcert, *walker, 1));
					walker++;
				}
			}
			break;
		}
	}
	E_g2e ("Failed to et the on-the-fly subject key",
		gnutls_x509_crt_set_key (otfcert, onthefly_subjectkey));
	/* TODO: The lock below should not be necessary; it is handled by p11-kit
	 *       or at least it ought to be.  What I found however, was that
	 *       a client and server would try to use the onthefly_issuerkey
	 *       at virtually the same time, and then the second call to
	 *       C_SignInit returns CKR_OPERATION_ACTIVE.  The lock solved this.
	 *       This makes me frown about server keys stored in PKCS #11...
	 */
{gnutls_datum_t data = { 0, 0}; if (gnutls_x509_crt_print (otfcert, GNUTLS_CRT_PRINT_UNSIGNED_FULL, &data) == 0) { fprintf (stderr, "DEBUG: PRESIGCERT: %s\n", data.data); gnutls_free (data.data); } else {fprintf (stderr, "DEBUG: PRESIGCERT failed to print\n"); } }
	assert (pthread_mutex_lock (&onthefly_signer_lock) == 0);
	E_g2e ("Failed to sign on-the-fly certificate",
		gnutls_x509_crt_privkey_sign (otfcert, onthefly_issuercrt, onthefly_issuerkey, GNUTLS_DIG_SHA256, 0));
	pthread_mutex_unlock (&onthefly_signer_lock);

	//
	// Construct cmd->lids [LID_TYPE_X509 - LID_TYPE_MIN].data+size for this certificate
	cmd->lids [LID_TYPE_X509 - LID_TYPE_MIN].size = 0;
	if (gtls_errno == GNUTLS_E_SUCCESS) {
		gtls_errno = gnutls_x509_crt_export (otfcert, GNUTLS_X509_FMT_DER, NULL, &cmd->lids [LID_TYPE_X509 - LID_TYPE_MIN].size);
		if (gtls_errno == GNUTLS_E_SHORT_MEMORY_BUFFER) {
			// This is as expected, now .size will have been set
			gtls_errno = GNUTLS_E_SUCCESS;
		} else {
			if (gtls_errno = GNUTLS_E_SUCCESS) {
				// Something must be wrong if we receive OK
				gtls_errno = GNUTLS_E_INVALID_REQUEST;
			}
		}
		E_g2e ("Error while measuring on-the-fly certificate size",
			gtls_errno);
	}
	uint8_t *ptr = NULL;
	if (gtls_errno == GNUTLS_E_SUCCESS) {
		cmd->lids [LID_TYPE_X509 - LID_TYPE_MIN].size += 4 + strlen (onthefly_p11uri) + 1;
		ptr = malloc (cmd->lids [LID_TYPE_X509 - LID_TYPE_MIN].size);
		if (ptr == NULL) {
			cmd->lids [LID_TYPE_X509 - LID_TYPE_MIN].size = 0;
			gnutls_x509_crt_deinit (otfcert);
			return GNUTLS_E_MEMORY_ERROR;
		}
	}
	if (ptr != NULL) {
		size_t restsz;
		cmd->lids [LID_TYPE_X509 - LID_TYPE_MIN].data = ptr;
		* (uint32_t *) ptr = htonl (LID_TYPE_X509 | LID_ROLE_BOTH);
		ptr += 4;
		strcpy (ptr, onthefly_p11uri);
		ptr += strlen (onthefly_p11uri) + 1;
		restsz = cmd->lids [LID_TYPE_X509 - LID_TYPE_MIN].size - 4 - strlen (onthefly_p11uri) - 1;
		E_g2e ("Failed to export on-the-fly certificate as a credential",
			gnutls_x509_crt_export (otfcert, GNUTLS_X509_FMT_DER, ptr, &restsz));
char *pembuf [10000];
size_t pemlen = sizeof (pembuf) - 1;
int exporterror = gnutls_x509_crt_export (otfcert, GNUTLS_X509_FMT_PEM, pembuf, &pemlen);
if (exporterror == 0) {
pembuf [pemlen] = '\0';
fprintf (stderr, "DEBUG: otfcert ::=\n%s\n", pembuf);
} else {
fprintf (stderr, "DEBUG: otfcert export to PEM failed with %d, gtls_errno already was %d\n", exporterror, gtls_errno);
}
	}

	//
	// Cleanup the allocated and built structures
	gnutls_x509_crt_deinit (otfcert);

	//
	// Return the overall result that might have stopped otf halfway
	return gtls_errno;
}

