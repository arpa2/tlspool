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
	pthread_t handler;
	struct tlspool_command cmd;
	//TODO// TLS-agnostic data would be a (void *) to a driver stack item:
	struct pioc_starttls *orig_starttls;
	DB_TXN *txn;
	pool_datum_t lids [EXPECTED_LID_TYPE_COUNT];
	int session_errno;
	intptr_t session_certificate;
	intptr_t session_privatekey;
	int anonpre;
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
 */
struct callback {
	struct callback *next;		/* Lists, e.g. free list or cbq list */
	int fd;
	pthread_cond_t semaphore;	/* Dependent is waiting for signal */
	struct command *followup;	/* Link to the callback returned cmd */
	int timedout;			/* Callback will be ignored, timeout */
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
void setup_service (void);
void cleanup_service (void);
void run_service (void);
void hangup_service (void);
void send_error (struct command *cmd, int tlserrno, char *msg);
void send_success (struct command *cmd);
int send_command (struct command *cmd, int passfd);
struct command *send_callback_and_await_response (struct command *cmdresp, time_t opt_timeout);

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
void starttls_prng (struct command *cmd);

/* config.c */
char *cfg_p11pin (void);
unsigned int cfg_log_perror (void);
unsigned int cfg_log_level (void);
unsigned int cfg_log_filter (void);
char *cfg_dbenv_dir (void);
char *cfg_db_localid (void);
char *cfg_db_disclose (void);
char *cfg_tls_dhparamfile (void);
unsigned int cfg_tls_maxpreauth (void);
uint32_t cfg_facilities (void);
char *cfg_tls_onthefly_signcert (void);
char *cfg_tls_onthefly_signkey (void);




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


/* The security_layer defines a value for each of the possible secure protocols.
 */
enum security_layer {
	security_tls,
};

/* The ctlkeynode structure is allocated (possibly on the stack) by each
 * thread that registers, until it unregisters.
 */
struct ctlkeynode {
	uint8_t ctlkey [TLSPOOL_CTLKEYLEN];
	struct ctlkeynode *lessnode, *morenode;
	int ctlfd;
	int forked;
	enum security_layer security;
};

/* The ctlkey_signalling_fd is a file descriptor that can be listened to in
 * poll() with revents==0; it will signal an error if it is closed.  The file
 * is in fact an open file descriptor for /dev/null and it will be replaced
 * by a new one in this variable before it is closed.  The closing however,
 * ensures that the poll() is interrupted and interrogation of changed
 * conditions, notably reattahed file descriptors, can be tried.
 */
//NOT// extern int ctlkey_signalling_fd;

/* Register a ctlkey and return 0 if it was successfully registered.  The
 * only reason for failure would be that the ctlkey is already registered,
 * which signifies an extremely unlikely clash -- or a program error by
 * not using properly scattered random sources.  The provided *ctlfdp may
 * be -1 to signal it is detached.  The forked flag should be non-zero
 * to indicate that this is a forked connection.
 */
int ctlkey_register (uint8_t *ctlkey, struct ctlkeynode *ckn, enum security_layer sec, int ctlfd, int forked);

/* Remove a registered cltkey value from th registry.  This is the most
 * complex operation, as it needs to merge the subtrees.
 *
 * This function returns non-zero iff it actually removed a node.  This
 * is useful because there may be other places from which this function
 * is called automatically.  Generally, the idea is to use a construct
 *	if (ctlkey_unregister (...)) {
 *		free (...);
 *      }
 */
int ctlkey_unregister (uint8_t *ctlkey);

/* Find a ctlkeynode based on a ctlkey.  Returns NULL if not found.
 * 
 * The value returned is the registered structure, meaning that any context
 * to the ctlkeynode returned can be relied upon.
 *
 * This also brings a responsibility to lock out other uses of the structure,
 * which means that a non-NULL return value must later be passed to a function
 * that unlocks the resource, ctlkey_unfind().
 */
struct ctlkeynode *ctlkey_find (uint8_t *ctlkey, enum security_layer sec, int ctlfd);

/* Free a ctlkeynode that was returned by ctlkey_find().  This function also
 * accepts a NULL argument, though those need not be passed through this
 * function as is the case with the non-NULL return values.
 *
 * The need for this function arises from the need to lock the structure, in
 * avoidance of access to structures that are being unregistered in another
 * thread.
 */
void ctlkey_unfind (struct ctlkeynode *ckn);

/* Dattach the given ctlkey, assuming it has clientfd as control connection.
 */
void ctlkey_detach (struct command *cmd);

/* Reattach to the given ctlkey, and use *ctlfdp as the controlling connection.
 * This function returns 0 on success, -1 on failure.
 */
void ctlkey_reattach (struct command *cmd);

/* Setup the ctlkey registry; notably, allocate the ctlkey_signalling_fd.
 */
void setup_ctlkey (void);

/* Cleanup the ctlkey registry.
 */
void cleanup_ctlkey (void);


/* Register an application socket as one that is willing to process LID entry
 * requests.  The file descriptor may also be used for other functions,
 * so it is only safe to use as a sending channel.  Registration is just
 * for one try, after which the application protocol will let it re-register.
 */
void register_lidentry_command (struct command *cmd);

/* Drop any LIDENTRY requests related to the given file descriptor, which is
 * being closed.  The LIDENTRY facility is freed up immediately for the next
 * requestor.
 */
void lidentry_forget_clientfd (int fd);

/* Check if the localid registration permits skipping of the given database
 * entry.  Such skips mean that the database entry on its own may fulfill the
 * completion of the localid value.  This takes into account all the
 * PIOF_LIDENTRY_SKIP_xxx flags registered by the client.
 *
 * The levels_up value counts 2 per step for domain names, and 1 per step for
 * user@domain identifiers.  So, with 0 for the concrete value, the low bit
 * indicates removal of a username and all higher bits refer to the steps up
 * in terms of a domain name.
 *
 * The at_root value indicates if this domain name is at the domain root,
 * irrespective of the existence or removal of usernames.
 *
 * This command is not run within a lock that protects against race conditions
 * related to registration of lidentry programs.  The reasoning is that the
 * re-registration infrastructure including timeouts suffices to keep these
 * programs registered once they have been, and when a program registers anew
 * there are bound to be such race condition opportunities.  It is useful to
 * have this property, as it also means that no lock is acquired no LID entry
 * for just checking if a database entry may just skip the callbacks.
 */
success_t lidentry_database_mayskip (int levels_up, int at_root);
/* Implement the function for localid callback with a database entry, as they
 * precede the localid inquiry callback.
 *
 * The maxlevels value counts 1 per step for domain names, and 1 per step for
 * user@domain identfiers.  The value 0 indicates the concrete value, which
 * is submitted in the remoteid parameter.  Note that maxlevels differs from
 * the levels_up parameter to lidentry_database_mayskip() in that domain names
 * are only half the value.
 *
 * This setup will claim the callback program, because a sequence of messages
 * must now be sent to it.  Without this sequence, the callback program would
 * get confusing mixtures of messages.  This implies a requirement to also
 * invoke lidentry_inquiry_callback(), as this is where any such lock will be
 * released; it is always the last in such sequences of messages.
 */
success_t lidentry_database_callback (char *remoteid, int maxlevels, char *localid);

/* Implement the function for localid inquiry callback.  This function will
 * contact the currently set LID handler connection.
 *
 * Upon returning failure, the localid and flags have not been changed.  This
 * means that it may be possible for the caller to setup defaults and process
 * the outcome regardless of success or failure of this function.
 */
success_t lidentry_inquiry_callback (char remoteid [128], int maxlevels, char localid [128], uint32_t *flags);

void setup_lidentry (void);
void cleanup_lidentry (void);

#endif //TLSPOOL_INTERNAL_H
