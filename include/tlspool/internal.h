/* tlspool/internal.h -- structures and definitions used inside the TLS pool */


#ifndef TLSPOOL_INTERNAL_H
#define TLSPOOL_INTERNAL_H

#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include <tlspool/commands.h>
#include <tlspool/starttls.h>

#include <db.h>

#ifdef HAVE_TLS_KDH
#include <krb5.h>
#endif


#define EXPECTED_LID_TYPE_COUNT 5

#define CERTS_MAX_DEPTH 10


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
	pool_handle_t clientfd;
	int passfd;
	int claimed;
	pthread_t handler;
	struct tlspool_command cmd;
	//TODO// TLS-agnostic data would be a (void *) to a driver stack item:
	struct pioc_starttls *orig_starttls;
	DB_TXN *txn;
	pool_datum_t lids [EXPECTED_LID_TYPE_COUNT];
	void *session;
	int session_errno;
	intptr_t session_certificate;
	intptr_t session_privatekey;
	char *trust_valexp;
	int valexp_result;
	int anonpre;
	char valflags [32];
	unsigned int vfystatus;
	int remote_auth_type;
	void *remote_cert_raw;
	int remote_cert_type;
	void *remote_cert [CERTS_MAX_DEPTH];
	uint8_t remote_cert_count;
#ifdef HAVE_TLS_KDH
	krb5_keyblock krb_key;		// Kerberos key for encryption
	krb5_principal krbid_cli;	// Kerberos clientID: Server || Client
	krb5_principal krbid_srv;	// Kerberos serverID: Server || KDH-Only
#endif
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
	pool_handle_t fd;           /* client socket receiving callback */
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
void register_server_socket (pool_handle_t srvsox);

/* pinentry.c */
void setup_pinentry (void);
void cleanup_pinentry (void);
void register_pinentry_command (struct command *cmd);
success_t token_callback (const char *const label, unsigned retry);
success_t pin_callback (int attempt, const char *token_url, const char *opt_prompt, char *pin, size_t pin_max);
void pinentry_forget_clientfd (pool_handle_t fd);

/* starttls.c */
void setup_starttls (void);
void cleanup_starttls (void);
void starttls_pkcs11_provider (char *p11path);
void starttls (struct command *cmd);
void starttls_prng (struct command *cmd);

/* config.c */
char *cfg_p11pin (void);
unsigned int cfg_log_perror (void);
unsigned int cfg_log_level (void);
unsigned int cfg_log_filter (void);
char *cfg_dbenv_dir (void);
char *cfg_db_localid (void);
char *cfg_db_disclose (void);
char *cfg_db_trust (void);
char *cfg_tls_dhparamfile (void);
unsigned int cfg_tls_maxpreauth (void);
uint32_t cfg_facilities (void);
char *cfg_tls_onthefly_signcert (void);
char *cfg_tls_onthefly_signkey (void);
char *cfg_dnssec_rootkey (void);
char *cfg_krb_client_keytab (void);
char *cfg_krb_server_keytab (void);
char *cfg_krb_client_credcache (void);
char *cfg_krb_server_credcache (void);


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
#define TLOG_KERBEROS	0x00010000


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
	pool_handle_t ctlfd;
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
int ctlkey_register (uint8_t *ctlkey, struct ctlkeynode *ckn, enum security_layer sec, pool_handle_t ctlfd, int forked);

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

/* Look through the ctlkey registry, to find sessions that depend on a closing
 * control connection meaning that they cannot survive it being closed;
 * those entries will be unregistered and deallocated ; this is used when a
 * client socket closes its link to the TLS Pool.
 *
 * This implementation closes all entries whose ctlfd matches; this is needed
 * for detached nodes that have been reattached.  Nodes that are attached
 * will usually be removed before they hit this routine, which is also good.
 *
 * Note that detached keys are (by definition) protected against this cleanup
 * procedure; however, when their TLS connection breaks down, they too will
 * be cleaned up.  Note that detaching is not done before the TLS handshake
 * is complete.
 */
void ctlkey_close_ctlfd (pool_handle_t clisox);

/* Find a ctlkeynode based on a ctlkey.  Returns NULL if not found.
 * 
 * The value returned is the registered structure, meaning that any context
 * to the ctlkeynode returned can be relied upon.
 *
 * This also brings a responsibility to lock out other uses of the structure,
 * which means that a non-NULL return value must later be passed to a function
 * that unlocks the resource, ctlkey_unfind().
 */
struct ctlkeynode *ctlkey_find (uint8_t *ctlkey, enum security_layer sec, pool_handle_t ctlfd);

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
void lidentry_forget_clientfd (pool_handle_t fd);

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


/********** VALIDATE.C FUNCTIONS **********/


struct valexp;


/* Setup the validation processing module.  This involves mapping the rather
 * unhandy valexpvarchars to a direct char-to-bitnum map.
 */
void setup_validate (void);


/* Cleanup the validation processing module.
 */
void cleanup_validate (void);


/* Support functions supplied by validation expression handlers.
 * Ideally, the handlers have asynchronous functions operated by handler_start()
 * and handler_stop().  The validation framework guarantees that it will never
 * call handler_start() more than once for a given registered handler_data, and
 * that it will call handler_stop() on all those before proceeding to
 * handler_final() to provide the final result of the validation process.
 * After handler_final(), there will be no more callbacks from the
 * validation framework.
 *
 * After calling handler_start() and before ending handler_stop(), it is
 * possible for the handler to report outcomes of the individual tests.
 *
 * Note that a sub-optimal implementation can be made by putting synchronous
 * code into handler_start(), letting it report its outcome and ignoring
 * handler_stop().  In light of potential timeouts, this can lead to long
 * waiting times detectable to users.
 */

struct valexp_handling {
	void (*handler_start) (void *handler_data, struct valexp *ve, char pred);
	void (*handler_stop ) (void *handler_data, struct valexp *ve, char pred);
	void (*handler_final) (void *handler_data, struct valexp *ve, bool value);
};


/* This is where a validation expression gets registered with the validation
 * processing framework.  The expressions are provided as a NULL-terminated
 * array of NUL-terminated strings, along with an uninitialised struct valexp
 * and a (void *) that will be used for callbacks to the handler functions.
 *
 * Every successful call to valexp_register() must be ended with a call to
 * valexp_unregister() to indicate that the using program has taken notice
 * of the termination of the processing by this module.  Before making this
 * call, there will usually be a notice to the handler function handle_final()
 * with the final value derived by this module, which may be taken as an
 * indication that the valexp module is ready with the work.  It is not
 * necessar however, to wait for this; if no such call has been made yet,
 * then it will be called later on.  Please note that the handle_final()
 * call may already be made during valexp_register(), as a result of the
 * and_expressions to evaluate to a definative value without delay.
 *
 * The client program will invoke valexp_unregister() when it wants to
 * terminate processing.  At this time, any pending computations will be
 * stopped, and a final result (failure, under the assumption of a timeout)
 * will be reported if this has not been done yet.
 *
 * MODIFICATION NOTE:
 * Although it is a diversion from common API logic, this routine may modify
 * the and_expression strings.  This is done to collect knowledge from the
 * static analysis of these strings.  The way in which this is done is
 * thread-safe, so global and/or static variables pose no problems even when
 * they are vigorously reused, but it is useful to understand that the strings
 * are not kept in tact.
 *
 * THREADING NOTE:
 * It is assumed that all invocations for this struct valexp will be made
 * from the same thread that invokes this function.  This greatly benefits
 * code simplicity.
 */
struct valexp *valexp_register (char **and_expressions,
				const struct valexp_handling *handler_functions,
				void *handler_data);


/* Every valexp_register() is undone with a call to valexp_unregister().
 * This makes the validation framework round off any pending checks and report
 * a final result, if this has not been done yet.
 *
 * THREADING NOTE:
 * It is assumed that this call is made by the same thread that registered
 * the validation expression, meaning that no threading occurs within the
 * handling of a validation expression.  This greatly benefits code simplicity.
 */
void valexp_unregister (struct valexp *ve);


/* Report the outcome of an individual predicate in a validation expression.
 * This may be done asynchronously, between the invocation of the handler_start()
 * and handler_stop() functions for the registered valexp.  It is not possible
 * to change the value for a predicate at a later time.
 *
 * THREADING NOTE:
 * It is assumed that this call is made by the same thread that registered
 * the validation expression, meaning that no threading occurs within the
 * handling of a validation expression.  This greatly benefits code simplicity.
 */
void valexp_setpredicate (struct valexp *ve, char predicate, bool value);


/* Pretty-print a valexp-structure.  This can be used to output the
 * folded-out structure, which may be helpful for debugging purposes.
 *
 * The printed structure is in infix notation, where AND is printed as
 * concatenation of letters and where ~ precedes the characters that
 * need to be all inverted.  The AND-combinations are ORed by a
 * separating "|" with a white space on each side.  Special cases may
 * be written as 0 or 1, namely an empty case or a an empty case list.
 *
 * This structure can be potent for debugging, when used to print
 * developing structures as to-be-resolved constraints are removed.
 *
 * This function must be called with buflen >= 4 so there is always
 * room to end with "...", which  is what this function will do at the
 * end of the buffer when buflen would otherwise be exceeded.
 */
void snprint_valexp (char *buf, int buflen, struct valexp *ve);


/********** online.c definitions **********/


void setup_online (void);
void cleanup_online (void);

/* Error levels: Proven correct, uncertain due to missing online info, or
 * proven wrong.
 */
#define ONLINE_SUCCESS  0
#define ONLINE_NOTFOUND 1
#define ONLINE_INVALID  2

typedef int (*online2success_t) (int online);
int online2success_enforced (int online);
int online2success_optional (int online);

/* Check an X.509 end certificate or a concatenation of X.509 certificates
 * from end certificate to root certificate against the global directory.
 * Take care that the second use assumes mere binary concatenation, rather
 * than the ASN.1 type SEQUENCE OF Certificate.
 */
int online_globaldir_x509 (char *rid, uint8_t *data, uint16_t len);

/* Check an OpenPGP public key, provided in binary form, against the global
 * directory.
 * Note that public keys are isolated and compared; the role of identities
 * is in finding the keys but not in checking whether they are contained
 * within the keys.
 */
int online_globaldir_pgp (char *rid, uint8_t *data, uint16_t len);

#endif //TLSPOOL_INTERNAL_H
