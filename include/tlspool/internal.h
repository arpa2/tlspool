/* tlspool/internal.h -- structures and definitions used inside the TLS pool */


#ifndef TLSPOOL_INTERNAL_H
#define TLSPOOL_INTERNAL_H

#include <tlspool/commands.h>

#include <gnutls/gnutls.h>

#include <db.h>


#define EXPECTED_LID_TYPE_COUNT 4


/* The command structure contains the literal packet and additional
 * information for local administrative purposes.
 */
struct command {
	int clientfd;
	int passfd;
	int claimed;
	pthread_t handler;
	struct tlspool_command cmd;
	struct pioc_starttls *orig_piocdata;
	DB_TXN *txn;
	gnutls_datum_t lids [EXPECTED_LID_TYPE_COUNT];
	gnutls_pcert_st *session_pcert;
	gnutls_privkey_t session_pkey;
};


/* The soxinfo structure defines information about sockets.  These will be
 * listed at the same index as in the pollfd structure list.
 */
struct soxinfo {
	uint32_t flags;			// See SOF_xxx below
	struct callback *cbq;		// Callback Queue
};

/* Server socket, use accept() only */
#define SOF_SERVER	0x00000001
/* Client socket, use normal recvmsg() and sendmsg() operations */
#define SOF_CLIENT	0x00000002
/* This socket claimed the PIN, check to see if it still holds it */
#define SOF_PINCLAIM	0x00000004


/* The callback structure defines information about callbacks, and supports
 * finding back a response to the application that should return a new
 * request.  It is used to trigger a thread that is waiting for input from
 * the application.  The index in this table is used as the callback identity,
 * which is not insecure because we assign it to a specific file descriptor.
 * The fd field can be negative to indicate an entry that is not in use.
 * TODO: Callbacks could time out -- or is that covered with fd teardown?
 */
struct callback {
	struct callback *next;		/* Lists, e.g. free list or cbq list */
	int fd;
	pthread_cond_t semaphore;	/* Dependent is waiting for signal */
	struct command *followup;	/* Link to the callback returned cmd */
};



/**************************** FUNCTIONS ******************************/



/* config.c */
void parse_cfgfile (char *filename, int kill_competition);

/* service.c */
void run_service (void);
void hangup_service (void);
void send_error (struct command *cmd, int tlserrno, char *msg);
int send_command (struct command *cmd, int passfd);
struct command *send_callback_and_await_response (struct command *cmdresp);

/* pinentry.c */
void setup_pinentry (void);
void cleanup_pinentry (void);
void register_pinentry_command (struct command *cmd);
int gnutls_pin_callback (void *userdata,
                                int attempt,
                                const char *token_url,
                                const char *token_label,
                                unsigned int flags,
                                char *pin,
                                size_t pin_max);

/* handler.c */
void setup_handler (void);
void cleanup_handler (void);
void starttls_client (struct command *cmd);
void starttls_server (struct command *cmd);

/* remote.c */
int ldap_fetch_openpgp_cert (gnutls_openpgp_crt_t *pgpcrtdata, char *localid);


/* config.c */
char *cfg_p11pin (void);
unsigned int cfg_log_perror (void);
unsigned int cfg_log_level (void);
unsigned int cfg_log_filter (void);
char *cfg_dbenv_dir (void);
char *cfg_db_localid (void);
char *cfg_db_disclose (void);
char *cfg_tls_dhparamfile (void);




/* error.c -- Mapping various error code systems to others.
 *
 * These macros assume the presence of error variables in the context, and
 * provide a shorthand to continue execution dependent on this variable.
 * The classical errno variable is used too, because it is thread-safe.
 *
 * GnuTLS errors are stored in gtls_errno and also mapped to errno values.
 * If either is set, the GnuTLS call is not made.  Note that all errors are
 * treated as fatal; use gnutls_error_is_fatal to recover in case of coubt.
 *
 * DB errors are mapped to both gtls_errno and errno.  If either is set,
 * the DB call is not made.  Note that all errors are treated as fatal;
 * check for known values (like DB_NOT_FOUND) to recover in case of doubt.
 *
 * The macro have_error_codes() can be used to check if either errno or
 * gtls_errno is set; this can be used to run a test before executing a
 * function that is later provided to the E_x2y functions.
 */

void setup_error (void);
void cleanup_error (void);
typedef int gtls_error;
typedef int db_error;

#define have_error_codes() ((gtls_errno != GNUTLS_E_SUCCESS) || (errno != 0))

/* Map a DB call (usually a function call) to errno and GnuTLS errvar
 * gtls_errno, optionally printing an errstr to avoid loosing information.
 * Define gtls_errno globally; process errno too, as an additional error system.
 * Skip if gtls_errno is not GNUTLS_E_SUCCESS but continue if errno is not 0. */
#define E_d2ge(errstr,dbcall) { \
	if (gtls_errno == 0) { \
		int _db_errno = (dbcall); \
		if (_db_errno != 0) { \
			error_db2gnutls2posix (&gtls_errno, _db_errno, (errstr)); \
		} \
	} \
}

/* Map a GnuTLS call (usually a function call) to a POSIX errno,
 * optionally reporting an errstr to avoid loosing information.
 * Retain errno if it already exists.
 * Continue if errno differs from 0, GnuTLS may "damage" it even when OK. */
#define E_g2e(errstr,gtlscall) { \
	if (gtls_errno == GNUTLS_E_SUCCESS) { \
		int gtls_errno = (gtlscall); \
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

/* Workhorse functions to map error systems, concealed by shorthand macros
 * defined below.
 */
void error_db2gnutls2posix (int *gtls_errno, int db_errno, char *opt_errstr);
void error_gnutls2posix (int gtls_errno, char *opt_errstr);


/* Log a message to syslog (assuming that the configuration wants it) */
void tlog (unsigned int logmask, int priority, char *format, ...);


/* Loglevel masking words, to help weed out logging output */
#define TLOG_TLS	0x00000001
#define TLOG_PKCS11	0x00000002
#define TLOG_DB		0x00000004
#define TLOG_FILES	0x00000008
#define TLOG_CRYPTO	0x00000010
#define TLOG_CERT	0x00000020
#define TLOG_USER	0x00000100
// Unused: #define TLOG_AUTHN	0x00000200
// Unused: #define TLOG_AUTHZ	0x00000400
// Unused: #define TLOG_CREDS	0x00000800
// Unused: #define TLOG_SESSION	0x00001000
#define TLOG_COPYCAT	0x00002000
#define TLOG_UNIXSOCK	0x00004000
#define TLOG_DAEMON	0x00008000

#endif //TLSPOOL_INTERNAL_H
