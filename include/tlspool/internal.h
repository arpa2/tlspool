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

#endif //TLSPOOL_INTERNAL_H
