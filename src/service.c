/* tlspool/service.c -- TLS pool service, socket handling, command dispatcher */

#include "whoami.h"

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <pthread.h>
#include <assert.h>

#include <errno.h>
#include <com_err.h>
#include <errortable.h>

#ifndef WINDOWS_PORT
#include <unistd.h>
#endif /* WINDOWS_PORT */

#include <syslog.h>
#include <fcntl.h>

#include <tlspool/commands.h>
#include <tlspool/internal.h>

#ifdef WINDOWS_PORT
#include <winsock2.h>
#else
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <poll.h>
#endif

#ifdef WINDOWS_PORT
#include <windows.h>
#ifndef __MINGW64__
#define WEOF ((wint_t)(0xFFFF))
#endif

#define _tprintf printf
#define _tmain main
#endif /* WINDOWS_PORT */

/* The data stored in this module consists of lists of sockets to listen to
 * for connection setup and command exchange, but not data communication.
 * Commands are received from the various clients and processed, always
 * ensuring exactly one reply.
 *
 * Some command requests are actually callbacks in reaction to something
 * the TLS pool sent to an application.  Those callbacks are recognised
 * by their pio_cbid parameter, and after security scrutiny they are passed
 * on directly to the requester, bypassing normal command processing and
 * instead processing it where it was requested.  This parser-like spread
 * of acceptable cases over processing nodes simplifies the complexity
 * and available alternatives in each node.  It also helps to benefit from
 * overlap between (semantics versions of) similar commands.
 *
 * Anything that may take up more than a trivial amount of time (perhaps
 * because it must wait for remote operations to complete) is sent off to
 * a separate thread, which may interact with its client or with a client
 * serving a special purpose (that is, the PIN entry client).
 *
 * When a thread wants to request a callback, it sends a command response
 * to that end, after creating a suitable structure in the callback list.
 * This structure includes a place where the callback command can be
 * stored, and a mutex that must be unlocked when that has been done.  The
 * callback structure may at that point be released.  The structures for
 * these exchanges with the callback list and, complicating matters, the
 * free list of callback structures, is arranged in this module and offered
 * to the rest of the TLS pool as an abstract service.
 */


static int stop_service = 0;
static uint32_t facilities;

static struct callback cblist [1024];
static struct callback *cbfree;
static pthread_mutex_t cbfree_mutex = PTHREAD_MUTEX_INITIALIZER;

static int os_send_command (struct command *cmd, int passfd);
static void os_run_service ();

/* Setup the service module.
 */
void setup_service (void) {
	facilities = cfg_facilities ();
}

/* Cleanup the service module.
 */
void cleanup_service (void) {
	;
}


/* Allocate a free command structure for the processing cycle.  Commands are
 * considered claimed between allocate_command_for_clientfd() and the freeing
 * of the command that takes place while sending a reply.  Note that sending
 * a callback request does not count as a reply; it defers the freeing-up of
 * the command structure.
 *
 * As for locking... this function is only called by the master thread, so
 * it requires no locks.  It merely sets the "claimed" flag (after setting
 * up the "clientfd" field) after which it is airborne.  Unlocking is done
 * by the thread that happens to be working on the command at that time,
 * and is effectively done by resetting the "claimed" flag to zero, and not
 * doing _anything_ with the command afterwards.
 */
static struct command *cmdpool = NULL;
static int cmdpool_len = 1000;
static struct command *allocate_command_for_clientfd (pool_handle_t fd) {
	static int cmdpool_pos = 0;
	int pos;
	struct command *cmd;
	if (!cmdpool) {
		cmdpool = (struct command *) calloc (1000, sizeof (struct command));
		if (!cmdpool) {
			tlog (TLOG_UNIXSOCK, LOG_CRIT, "Failed to allocate command pool");
			exit (1);
		}
		memset (cmdpool, 0, 1000 * sizeof (struct command));
	}
	pos = cmdpool_pos;
	while (cmdpool [pos].claimed) {
		pos++;
		if (pos >= cmdpool_len) {
			cmdpool = 0;
		}
		if (pos == cmdpool_pos) {
			/* A full rotation -- delay of 10ms */
			_usleep (10000);
		}
	}
	cmdpool [pos].clientfd = fd;
	cmdpool [pos].passfd = -1;
	cmdpool [pos].handler = pthread_self ();	// Not fit for cancel
	cmdpool [pos].claimed = 1;
	return &cmdpool [pos];
}


/* Free any commands that were allocated to the given client file descriptor.
 * This is disruptive; the commands will not continue their behaviour by
 * responding to the requests.  This means that it should only be used for
 * situations where the client file descriptor was closed.
 * Any threads that may be running or waiting on the command are cancelled.
 *
 * TODO: This is O(cmdpool_len) so linked lists could help to avoid trouble.
 */
static void free_commands_by_clientfd (pool_handle_t clientfd) {
	int i;
	if (cmdpool == NULL) {
		return;
	}
	for (i=0; i<cmdpool_len; i++) {
		if (cmdpool [i].claimed) {
			if (cmdpool [i].clientfd == clientfd) {
				//TODO// don't be so disruptive
				pthread_cancel (cmdpool [i].handler);
				cmdpool [i].claimed = 0;
			}
		}
	}
}

int send_command (struct command *cmd, int passfd) {
	int rc;

	if (cmd == NULL) {
		return 1;	// Success guaranteed when nobody is listening
	}
	assert (passfd == -1);	// Working passfd code retained but not used
	cmd->claimed = 0;
	return os_send_command(cmd, passfd);
}

/* Report success to the user.  Note that this function does not terminate
 * actions, but it should be the last response to the client.
 *
 * We accept the situation where cmd==NULL to accommodate code that deals
 * with re-run commands that were internally stored.  This saves massively
 * in re-coding such code.
 *
 * We accept the situation where cmd==NULL to accommodate code that deals
 * with re-run commands that were internally stored.  This saves massively
 * in re-coding such code.
 */
void send_success (struct command *cmd) {
	if (cmd == NULL) {
		return;
	}
	cmd->cmd.pio_cmd = PIOC_SUCCESS_V2;
	cmd->cmd.pio_cbid = 0;
	if (!send_command (cmd, -1)) {
		perror ("Failed to send success reply");
	}
}


/* Report an error response to the user.  Report with the given errno and msg.
 * Note that this function does not terminate actions, but it should be the
 * last response to the client.
 *
 * We accept the situation where cmd==NULL to accommodate code that deals
 * with re-run commands that were internally stored.  This saves massively
 * in re-coding such code.
 */
void send_error (struct command *cmd, int tlserrno, char *msg) {
	if (cmd == NULL) {
		return;
	}
	if (tlserrno == 0) {
		send_success (cmd);
		return;
	}
	cmd->cmd.pio_cmd = PIOC_ERROR_V2;
	cmd->cmd.pio_cbid = 0;
	cmd->cmd.pio_data.pioc_error.tlserrno = tlserrno;
	strncpy (cmd->cmd.pio_data.pioc_error.message, msg, sizeof (cmd->cmd.pio_data.pioc_error.message));
	if (!send_command (cmd, -1)) {
		perror ("Failed to send error reply");
	}
}

void copy_tls_command(struct command *cmd, struct tlspool_command *tls_command) {
	memcpy(&cmd->cmd, tls_command, sizeof(struct tlspool_command));
}

/* Check if a command request is a proper callback response.
 * Return 1 if it is, othterwise return 0.
 */
static int is_callback (struct command *cmd) {
	uint16_t cbid = cmd->cmd.pio_cbid;
	if (cbid == 0) {
		return 0;
	}
	if (cbid > 1024) {	/* TODO: dynamicity */
		return 0;
	}
	cbid--;
	if (cblist [cbid].fd < 0) {
		return 0;
	}
	if (cblist [cbid].fd != cmd->clientfd) {
		return 0;
	}
	if (cblist [cbid].followup) {
		return 0;
	}
	return 1;
}


/* Desire a callback and in the process of doing so, send a callback response.
 * This must be called from another thread than the main TLS pool thread.
 *
 * The code below and the signaling post_callback call claim the cbfree_mutex
 * as a condition to protect (keep atomic) the conditioning and signaling.
 * The condition awaited for which the callback's condition presents a hint
 * is the setting of the followup pointer in the callback structure, which
 * links in the command that responds to the callback placed.
 *
 * The caller may supply the absolute time_t value at which it times out.
 * If opt_timeout is 0, it is not considered to be a timeout value.  If it
 * is supplied, the return value may be NULL to signal timeout.  There is
 * no information fed back from the caller, but at least the TLS Pool does
 * not block on it, but can continue to process failure.  Later submissions
 * of the callback response are swallowed silently (although a log entry
 * will be made).
 */
struct command *send_callback_and_await_response (struct command *cmdresp, time_t opt_timeout) {
	struct callback *cb;
	struct command *followup;
	assert (pthread_mutex_lock (&cbfree_mutex) == 0);
	cb = cbfree;
	if (!cb) {
		//TODO// Allocate more...
		tlog (TLOG_UNIXSOCK, LOG_CRIT, "Ran out of callback structures.  Crashing as a coward");
		exit (1);
	}
	//TODO// It's simpler to administer index numbers and not pointers
	cbfree = cb->next;
	cmdresp->cmd.pio_cbid = 1 + (((intptr_t) cb) - ((intptr_t) cblist)) / ((intptr_t) sizeof (struct callback));
	cb->fd = cmdresp->clientfd;
	cb->followup = NULL;
	cb->next = NULL; //TODO// Enqueue in fd-queue
	cb->timedout = 0;
	send_command (cmdresp, -1);
	do {
		tlog (TLOG_UNIXSOCK, LOG_DEBUG, "Waiting with fd=%d and cbid=%d on semaphone 0x%08x", cb->fd, cmdresp->cmd.pio_cbid, cb);
		if (opt_timeout != 0) {
			struct timespec ts;
			memset (&ts, 0, sizeof (ts));
			ts.tv_sec = opt_timeout;
			if (pthread_cond_timedwait (&cb->semaphore, &cbfree_mutex, &ts) != 0) {
				// Timed out (or interrupted) so give up
				followup = NULL;
				break;
			}
		} else {
			pthread_cond_wait (&cb->semaphore, &cbfree_mutex);
		}
		followup = cb->followup;
	} while (!followup);
	//TODO// Remove cb from the fd's cblist
	if (followup) {
		cb->next = cbfree;
		cbfree = cb;
	} else {
		cb->timedout = 1;	// Defer freeing it to the signaler
	}
	pthread_mutex_unlock (&cbfree_mutex);
	if (!followup) {
		tlog (TLOG_UNIXSOCK, LOG_NOTICE, "Requested callback over %d timed out, cleanup of structures deferred", cmdresp->clientfd);
	}
	return followup;
}


/* Present a callback command request to the thread that is waiting for it.
 * This must be called from the main thread of the TLS pool, and it will
 * spark life to the thread that is awaiting the callback.
 */
static void post_callback (struct command *cmd) {
	uint16_t cbid = cmd->cmd.pio_cbid - 1;
	cblist [cbid].fd = INVALID_POOL_HANDLE;
	cblist [cbid].followup = cmd;
	assert (pthread_mutex_lock (&cbfree_mutex) == 0);
	tlog (TLOG_UNIXSOCK, LOG_DEBUG, "Signaling on the semaphore of callback 0x%08x", &cblist [cbid]);
	if (!cblist [cbid].timedout) {
		// Still waiting, send a signal to the requester
		pthread_cond_signal (&cblist [cbid].semaphore);
	} else {
		// Timed out, but the callback structure awaits cleanup
		cblist [cbid].next = cbfree;
		cbfree = &cblist [cbid];
		cmd->claimed = 0;
		//TODO// Might report an error back, to indicate ignorance
	}
	pthread_mutex_unlock (&cbfree_mutex);
}


/* Forget all callbacks that were sent to the given clientfd, by posting an
 * ERROR message to them.  This is used to avoid infinitely waiting threads
 * in the TLS Pool when a clientfd is closed by the client (perhaps due to
 * a crash in response to the callback).
 */
static void free_callbacks_by_clientfd (pool_handle_t clientfd) {
	int i;
	for (i=0; i<1024; i++) {
//TODO// == clientfd was >= 0 (and managed to get closes sent back to all)
		if (cblist [i].fd == clientfd) {
			struct command *errcmd;
			errcmd = allocate_command_for_clientfd (clientfd);
			errcmd->clientfd = clientfd;
			errcmd->passfd = -1;
			errcmd->claimed = 1;
			errcmd->cmd.pio_reqid = 0;  // Don't know how to set it
			errcmd->cmd.pio_cbid = i + 1;
			errcmd->cmd.pio_cmd = PIOC_ERROR_V2;
			errcmd->cmd.pio_data.pioc_error.tlserrno = E_TLSPOOL_CLIENT_DISCONNECT;
			snprintf (errcmd->cmd.pio_data.pioc_error.message, 127, "TLS Pool client fd %d closed", clientfd);
printf ("DEBUG: Freeing callback with cbid=%d for clientfd %d\n", i+1, clientfd);
			post_callback (errcmd);
printf ("DEBUG: Freed   callback with cbid=%d for clientfd %d\n", i+1, clientfd);
		}
	}
}


/* Process an info query; it depends on what is being asked,
 * where it should be directed.  Not everything is TLS :-)
 */
static void  process_command_info (struct command *cmd) {
	uint8_t *ctlkey = cmd->cmd.pio_data.pioc_info.ctlkey;
	uint32_t kind   = cmd->cmd.pio_data.pioc_info.info_kind;
	uint16_t len    = cmd->cmd.pio_data.pioc_info.len;
	uint8_t *buf    = cmd->cmd.pio_data.pioc_info.buffer;
	//
	// Is the control key valid?
	struct ctlkeynode *node = ctlkey_find (cmd->cmd.pio_data.pioc_info.ctlkey, security_tls, cmd->clientfd);
	if (node == NULL) {
		send_error (cmd, E_TLSPOOL_CTLKEY_NOT_FOUND,
					"TLS Pool cannot find the control key");
		goto done;
	}
	//
	// Ensure proper sizing of the request
	if ((len > sizeof (cmd->cmd.pio_data.pioc_info.buffer)) && (len != 0xffff)) {
		send_error (cmd, E_TLSPOOL_COMMAND_NOTIMPL, "TLS Pool command or variety not implemented");
		goto done_unfind;
	}
	//
	// Invoke a handler specific to the kind of information
	switch (kind) {
	case PIOK_INFO_PEERCERT_SUBJECT:
	case PIOK_INFO_MYCERT_SUBJECT:
		starttls_info_cert_subject (cmd, node, len, buf);
		break;
	case PIOK_INFO_PEERCERT_ISSUER:
	case PIOK_INFO_MYCERT_ISSUER:
		starttls_info_cert_issuer (cmd, node, len, buf);
		break;
	case PIOK_INFO_PEERCERT_SUBJECTALTNAME:
	case PIOK_INFO_MYCERT_SUBJECTALTNAME:
		starttls_info_cert_subjectaltname (cmd, node, len, buf);
		break;
	case PIOK_INFO_CHANBIND_TLS_UNIQUE:
		starttls_info_chanbind_tls_unique (cmd, node, len, buf);
		break;
	case PIOK_INFO_CHANBIND_TLS_SERVER_END_POINT:
		starttls_info_chanbind_tls_server_end_point (cmd, node, len, buf);
		break;
	default:
		send_error (cmd, E_TLSPOOL_INFOKIND_UNKNOWN, "TLS Pool does not support that kind of info");
		break;
	}
	//
	// Cleanup; this involves unlocking the ctlkey to other messages
done_unfind:
	ctlkey_unfind (node);
done:
	;
}


/* Process a command packet that entered on a TLS pool socket
 */
static void process_command (struct command *cmd) {
	tlog (TLOG_UNIXSOCK, LOG_DEBUG, "Processing command 0x%08x, passfd=%d", cmd->cmd.pio_cmd, cmd->passfd);
	union pio_data *d = &cmd->cmd.pio_data;
	if (is_callback (cmd)) {
printf ("DEBUG: Processing callback command sent over fd=%d\n", cmd->clientfd);
		post_callback (cmd);
		return;
	}
	switch (cmd->cmd.pio_cmd) {
	case PIOC_PING_V2:
		strcpy (d->pioc_ping.YYYYMMDD_producer, TLSPOOL_IDENTITY_V2);
		d->pioc_ping.facilities &= facilities;
		send_command (cmd, -1);
		return;
	case PIOC_STARTTLS_V2:
		starttls (cmd);
		return;
	case PIOC_PRNG_V2:
		if (facilities & PIOF_FACILITY_STARTTLS) {
			starttls_prng (cmd);
		} else {
			send_error (cmd, E_TLSPOOL_FACILITY_STARTTLS,
				"TLS Pool setup excludes STARTTLS facility");
		}
		return;
	case PIOC_INFO_V2:
		process_command_info (cmd);
		return;
	case PIOC_CONTROL_DETACH_V2:
		ctlkey_detach (cmd);
		return;
	case PIOC_CONTROL_REATTACH_V2:
		ctlkey_reattach (cmd);
		return;
#ifndef WINDOWS_PORT
	case PIOC_PINENTRY_V2:
		register_pinentry_command (cmd);
		return;
#endif
	case PIOC_LIDENTRY_REGISTER_V2:
		register_lidentry_command (cmd);
		return;
	default:
		send_error (cmd, E_TLSPOOL_COMMAND_UNKNOWN, "TLS Pool command unrecognised");
		return;
	}
}

/* Request orderly hangup of the service.
 */
void hangup_service (void) {
	stop_service = 1;
	tlog (TLOG_UNIXSOCK, LOG_NOTICE, "Requested service to hangup soon");
}

/* The main service loop.  It uses poll() to find things to act upon. */
void run_service (void) {
	int i;

	cbfree = NULL;
	errno = pthread_setcancelstate (PTHREAD_CANCEL_DISABLE, NULL);
	if (errno) {
		tlog (TLOG_UNIXSOCK | TLOG_DAEMON, LOG_ERR, "Service routine thread cancellability refused");
		exit (1);
	}
	for (i=0; i<1024; i++) {
		cblist [i].next = cbfree;
		cblist [i].fd = INVALID_POOL_HANDLE; // Mark as unused
		pthread_cond_init (&cblist [i].semaphore, NULL);
		cblist [i].followup = NULL;
		cbfree = &cblist [i];
	}
	os_run_service ();
}

#ifdef WINDOWS_PORT
#include "service_windows.c"
#else
#include "service_posix.c"
#endif

