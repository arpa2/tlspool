/* error.c -- Map error codes between the various error subsystems.
 *
 * From: Rick van Rein <rick@openfortress.nl>
 */


#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>

#include <syslog.h>
#include <errno.h>

#include <db.h>

#include <gnutls/gnutls.h>
#include <gnutls/abstract.h>

#include <tlspool/internal.h>


/* Data structures for logging configuration */

static unsigned int log_filter;


/* Setup logging structures for error reporting.
 */
void setup_error (void) {
	unsigned int log_perror;
	unsigned int log_level;
	log_perror = cfg_log_perror ();
	log_level = cfg_log_level ();
	log_filter = cfg_log_filter ();
	openlog ("TLS Pool", LOG_CONS | LOG_PID | log_perror, log_level);
}

void cleanup_error (void) {
	closelog ();
}


/* Forward a message to syslog, assuming that the configuration wants it */

void tlog (unsigned int logmask, int priority, char *format, ...) {
	va_list varg;
	va_start (varg, format);
	if ((logmask & log_filter) != 0) {
		vsyslog (priority, format, varg);
	}
	va_end (varg);
}



/* Mapping for error codes between the various subsystems in use. */

void error_db2gnutls2posix (int *gtls_errno, int db_errno, char *opt_errstr) {
	if (db_errno == 0) {
		return;
	}
	if (opt_errstr) {
		tlog (TLOG_DB, LOG_ERR, "DB error: %s", opt_errstr);
	}
	if (errno == 0) {
		switch (db_errno) {
		case DB_BUFFER_SMALL:
		case DB_LOG_BUFFER_FULL:
			errno = ENOBUFS;
			break;
		case DB_DONOTINDEX:
		case DB_KEYEMPTY:
		case DB_FOREIGN_CONFLICT:
		case DB_PAGE_NOTFOUND:
		case DB_SECONDARY_BAD:
			errno = ENOKEY;
			break;
		case DB_KEYEXIST:
			errno = EACCES;
			break;
		case DB_LOCK_DEADLOCK:
			errno = EDEADLK;
			break;
		case DB_LOCK_NOTGRANTED:
			errno = ENOLCK;
			break;
		case DB_NOSERVER:
		case DB_NOSERVER_HOME:
		case DB_NOSERVER_ID:
		case DB_REP_DUPMASTER:
		case DB_REP_HANDLE_DEAD:
		case DB_REP_HOLDELECTION:
		case DB_REP_IGNORE:
		case DB_REP_ISPERM:
		case DB_REP_JOIN_FAILURE:
		case DB_REP_LEASE_EXPIRED:
		case DB_REP_LOCKOUT:
		case DB_REP_NEWSITE:
		case DB_REP_NOTPERM:
		case DB_REP_UNAVAIL:
			errno = EREMOTEIO;
			break;
		case DB_NOTFOUND:
			errno = ENODATA;
			break;
		case DB_OLD_VERSION:
		case DB_VERSION_MISMATCH:
			errno = ENOEXEC;
			break;
		case DB_RUNRECOVERY:
		case DB_VERIFY_BAD:
			errno = ENOTRECOVERABLE;
			break;
		default:
			errno = ENOSYS;
			break;
		}
	}
	if (*gtls_errno == GNUTLS_E_SUCCESS) {
		*gtls_errno = GNUTLS_E_DB_ERROR;
	}
}

void error_gnutls2posix (int gtls_errno, char *opt_errstr) {
	register int newerrno;
	if (gtls_errno == GNUTLS_E_SUCCESS) {
		return;
	}
	if (errno != 0) {
		return;
	}
	tlog (TLOG_TLS, LOG_ERR, "%s: %s",
		opt_errstr? opt_errstr: "GnuTLS error",
		gnutls_strerror (gtls_errno));
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
		newerrno = ENODATA;
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
		newerrno = EREMOTEIO;
		break;
	default:
		newerrno = EIO;
		break;
	}
	errno = newerrno;
	return;
}
