/* tlspool/internal.h -- structures and definitions used inside the TLS pool */


#ifndef TLSPOOL_INTERNAL_H
#define TLSPOOL_INTERNAL_H

#include <tlspool/commands.h>


/* The command structure contains the literal packet and additional
 * information for local administrative purposes.
 */
struct command {
	int clientfd;
	int passfd;
	int claimed;
	pthread_t handler;
	pthread_mutex_t ownership;
	struct tlspool_command cmd;
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
	pthread_mutex_t lock;		/* Dependent is waiting for unlock */
	struct command **followup;	/* The callback command waited for */
};



/**************************** FUNCTIONS ******************************/



/* config.c */
void parse_cfgfile (char *filename, int kill_competition);

/* service.c */
void run_service (void);
void send_error (struct command *cmd, int tlserrno, char *msg);
int send_command (struct command *cmd, int passfd);

/* pinentry.c */
void setup_pinentry (void);
void register_pinentry_command (struct command *cmd);

/* handler.c */
void setup_handler (void);
void starttls_client (struct command *cmd);
void starttls_server (struct command *cmd);


#endif //TLSPOOL_INTERNAL_H
