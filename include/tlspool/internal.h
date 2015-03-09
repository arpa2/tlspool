/* tlspool/internal.h -- structures and definitions used inside the TLS pool */


#ifndef TLSPOOL_INTERNAL_H
#define TLSPOOL_INTERNAL_H

#include <stdint.h>

#include <tlspool/commands.h>

#include <db.h>


#define EXPECTED_LID_TYPE_COUNT 4


/* A simple (data*,size) construct named pool_datum_t
 */
typedef struct pool_datum {
	void *data;
	size_t size;
} pool_datum_t;


/* The command structure contains the literal packet and additional
 * information for local administrative purposes.
 */
struct command {
	int clientfd;
	int passfd;
	int claimed;
	int session_errno;
	pthread_t handler;
	struct tlspool_command cmd;
	struct pioc_starttls *orig_piocdata;
	DB_TXN *txn;
	pool_datum_t lids [EXPECTED_LID_TYPE_COUNT];
	intptr_t session_certificate;
	intptr_t session_privatekey;
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



/* An errno/errstr related return value; it is non-zero on success, and
 * zero on failure.  It is defined as a type to simplify API documentation
 * through this standardised response.
 */
typedef int success_t;


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
success_t token_callback (const char *const label, unsigned retry);
success_t pin_callback (int attempt, const char *token_url, const char *token_label, char *pin, size_t pin_max);

/* starttls.c */
void setup_starttls (void);
void cleanup_starttls (void);
void starttls_pkcs11_provider (char *p11path);
void starttls_client (struct command *cmd);
void starttls_server (struct command *cmd);

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
 * GnuTLS errors are mapped to errno/errstr values.  If either is set, the
 * GnuTLS call is not made.  Note that all errors are treated as fatal;
 * use gnutls_error_is_fatal to recover in case of coubt.
 *
 * DB errors are mapped to errno.  If either is set, the DB call is not
 * made.  Note that all errors are treated as fatal; check for known values
 * (like DB_NOT_FOUND) to recover in case of doubt.
 *
 * The macro have_error_codes() can be used to check if either errno or
 * gtls_errno is set; this can be used to run a test before executing a
 * function that is later provided to the E_x2y functions.
 */

void setup_error (void);
void cleanup_error (void);
typedef int gtls_error;
typedef int db_error;
char *error_getstring (void);
void error_setstring (char *);

#define have_error_codes() ((gtls_errno != GNUTLS_E_SUCCESS) || (errno != 0))

/* Map a DB call (usually a function call) to errno + errstr, optionally
 * printing an errstr to avoid loosing information.  The error number from
 * DB is stored in db_errno, which is assumed an available int. */
#define E_d2e(errstr,dbcall) { \
	if (db_errno == 0) { \
		db_errno = (dbcall); \
		if (db_errno != 0) { \
			error_db2posix (db_errno, (errstr)); \
		} \
	} \
}

/* Make the successcall only made when errno == 0; the return value from
 * the call should be of type success_t for detection of error and further
 * mapping of errno to errstr.  This is the POSIX counterpart of the GnuTLS
 * and DB macros above.
 * Set successcall to NULL to lap up any set values in errno that have not
 * explicitly been cleared.  In other words, the switch to errstr to determine
 * what to do has no implications (other than delay and ordering) on errno;
 * its errors will not be forgotten, lest they are explicitly cleared.
 */
#define E_e2e(errstr,successcall) { \
	if (errno == 0) { \
		if (! (successcall)) { \
			error_posix2strings (errstr); \
		} \
	} \
}

/* Cleanup when DBM leaves errno damaged but returns no db_errno */
#define E_db_clear_errno() { \
	if (db_errno == 0) { \
		errno = 0; \
	} \
}

/* Workhorse functions to map error systems, concealed by shorthand macros
 * defined below.
 */
void error_db2posix (int db_errno, char *errstr);
void error_posix2strings (char *errstr);


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
