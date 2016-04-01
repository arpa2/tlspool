/* tlspool/service.c -- TLS pool service, socket handling, command dispatcher */

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <pthread.h>
#include <assert.h>

#include <syslog.h>
#include <fcntl.h>
#include <poll.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <tlspool/commands.h>
#include <tlspool/internal.h>

#ifdef __CYGWIN__
#include <windows.h>
#define WEOF ((wint_t)(0xFFFF))

#define PIPE_TIMEOUT 5000
#define BUFSIZE 4096

#define _tprintf printf
#define _tmain main
#endif

#ifdef __CYGWIN__
typedef struct
{
	OVERLAPPED oOverlap;
	HANDLE hPipeInst;
	struct tlspool_command chRequest;
	DWORD cbRead;
//	struct command chReply;
	DWORD cbToWrite;
} PIPEINST, *LPPIPEINST;

VOID DisconnectAndClose(LPPIPEINST);
BOOL ConnectToNewClient(HANDLE, LPOVERLAPPED);
VOID GetAnswerToRequest(LPPIPEINST);

VOID WINAPI CompletedWriteRoutine(DWORD, DWORD, LPOVERLAPPED);
VOID WINAPI CompletedReadRoutine(DWORD, DWORD, LPOVERLAPPED);

extern char szPipename[1024];
HANDLE hPipe;
#endif

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


static struct soxinfo soxinfo [1024];
static struct pollfd soxpoll [1024];
static int num_sox = 0;
static int stop_service = 0;
static uint32_t facilities;

static struct callback cblist [1024];
static struct callback *cbfree;
static pthread_mutex_t cbfree_mutex = PTHREAD_MUTEX_INITIALIZER;


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
		bzero (cmdpool, 1000 * sizeof (struct command));
	}
	pos = cmdpool_pos;
	while (cmdpool [pos].claimed) {
		pos++;
		if (pos >= cmdpool_len) {
			cmdpool = 0;
		}
		if (pos == cmdpool_pos) {
			/* A full rotation -- delay of 10ms */
			usleep (10000);
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


/* Register a socket.  It is assumed that first all server sockets register */
void register_socket (pool_handle_t sox, uint32_t soxinfo_flags) {
	int flags = fcntl (sox, F_GETFD);
	flags |= O_NONBLOCK;
	fcntl (sox, F_SETFD, flags);
	//TODO// if (soxinfo == NULL) {
	//TODO// 	soxinfo = calloc ()
	//TODO// }
	if (num_sox == 1024) {
		tlog (TLOG_UNIXSOCK, LOG_CRIT, "Cannot allocate more than 1024 server sockets");
		exit (1);
	}
	soxpoll [num_sox].fd = sox;
	soxpoll [num_sox].events = POLLIN;
	soxpoll [num_sox].revents = 0;
	soxinfo [num_sox].flags = soxinfo_flags;
	soxinfo [num_sox].cbq = NULL;
	num_sox++;
}


void register_server_socket (pool_handle_t srvsox) {
	register_socket (srvsox, SOF_SERVER);
}


void register_client_socket (pool_handle_t clisox) {
	register_socket (clisox, SOF_CLIENT);
}


static void free_callbacks_by_clientfd (pool_handle_t clientfd);

/* TODO: This may copy information back and thereby avoid processing in the
 * current loop passthrough.  No problem, poll() will show it once more. */
static void unregister_client_socket_byindex (int soxidx) {
	pool_handle_t sox = soxpoll [soxidx].fd;
	free_callbacks_by_clientfd (sox);
	free_commands_by_clientfd (sox);
	pinentry_forget_clientfd (sox);
	lidentry_forget_clientfd (sox);
	ctlkey_close_ctlfd (sox);
	num_sox--;
	if (soxidx < num_sox) {
		memcpy (&soxinfo [soxidx], &soxinfo [num_sox], sizeof (*soxinfo));
		memcpy (&soxpoll [soxidx], &soxpoll [num_sox], sizeof (*soxpoll));
	}
}


int send_command (struct command *cmd, int passfd) {
	char anc [CMSG_SPACE(sizeof (int))];
	struct iovec iov;
	struct msghdr mh;
	struct cmsghdr *cmsg;

	if (cmd == NULL) {
		return 1;	// Success guaranteed when nobody is listening
	}
	assert (passfd == -1);	// Working passfd code retained but not used
#ifdef __CYGWIN__
	cmd->cmd.pio_ancil_type = ANCIL_TYPE_NONE;
	bzero (&cmd->cmd.pio_ancil_data, sizeof (cmd->cmd.pio_ancil_data));
#endif
	bzero (anc, sizeof (anc));
	bzero (&iov, sizeof (iov));
	bzero (&mh, sizeof (mh));
	iov.iov_base = &cmd->cmd;
	iov.iov_len = sizeof (cmd->cmd);
	mh.msg_iov = &iov;
	mh.msg_iovlen = 1;
#ifndef __CYGWIN__
	if (passfd >= 0) {
		mh.msg_control = anc;
		mh.msg_controllen = sizeof (anc);
		cmsg = CMSG_FIRSTHDR (&mh);
		cmsg->cmsg_level = SOL_SOCKET;
		cmsg->cmsg_type = SCM_RIGHTS;
		cmsg->cmsg_len = CMSG_LEN (sizeof (int));
		* (int *) CMSG_DATA (cmsg) = passfd;
	}
#endif
	tlog (TLOG_UNIXSOCK, LOG_DEBUG, "Sending command 0x%08x and fd %d to socket %d", cmd->cmd.pio_cmd, passfd, (int) cmd->clientfd);
	if (sendmsg (cmd->clientfd, &mh, MSG_NOSIGNAL) == -1) {
		//TODO// Differentiate behaviour based on errno?
		perror ("Failed to send command");
		cmd->claimed = 0;
		return 0;
	} else {
		tlog (TLOG_UNIXSOCK, LOG_DEBUG, "Sent command code 0x%08x", cmd->cmd.pio_cmd);
		cmd->claimed = 0;
		return 1;
	}
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


#ifndef __CYGWIN__
/* Receive a command.  Return nonzero on success, zero on failure. */
int receive_command (pool_handle_t sox, struct command *cmd) {
	int newfds [2];
	int newfdcnt = 0;
	char anc [CMSG_SPACE (sizeof (int))];
	struct iovec iov;
	struct msghdr mh = { 0 };
	struct cmsghdr *cmsg;

	iov.iov_base = &cmd->cmd;
	iov.iov_len = sizeof (cmd->cmd);
	mh.msg_iov = &iov;
	mh.msg_iovlen = 1;
	mh.msg_control = anc;
	mh.msg_controllen = sizeof (anc);

	if (recvmsg (sox, &mh, MSG_NOSIGNAL) == -1) {
		//TODO// Differentiate behaviour based on errno?
		perror ("Failed to receive command");
		return 0;
	}
	tlog (TLOG_UNIXSOCK, LOG_DEBUG, "Received command request code 0x%08x with cbid=%d over fd=%d", cmd->cmd.pio_cmd, cmd->cmd.pio_cbid, sox);

	cmsg = CMSG_FIRSTHDR (&mh);
	//TODO// It is more general to look at all FDs passed, close all 2+
	if (cmsg && (cmsg->cmsg_len == CMSG_LEN (sizeof (int)))) {
		if ((cmsg->cmsg_level == SOL_SOCKET) && (cmsg->cmsg_type == SCM_RIGHTS)) {
			if (cmd->passfd == -1) {
				cmd->passfd = * (int *) CMSG_DATA (cmsg);
				tlog (TLOG_UNIXSOCK, LOG_DEBUG, "Received file descriptor as %d", cmd->passfd);
			} else {
				int superfd = * (int *) CMSG_DATA (cmsg);
				tlog (TLOG_UNIXSOCK, LOG_ERR, "Received superfluous file descriptor as %d", superfd);
				close (superfd);
			}
		}
		cmsg = CMSG_NXTHDR (&mh, cmsg);
	}

	return 1;
}
#endif /* !__CYGWIN__ */


#ifdef __CYGWIN__
extern cygwin_socket_from_protocol_info (LPWSAPROTOCOL_INFOW lpProtocolInfo);

/* Receive a command.  Return nonzero on success, zero on failure. */
int receive_command (pool_handle_t sox, struct command *cmd) {
	if (recv(sox, &cmd->cmd, sizeof(cmd->cmd), 0) == -1) {
		//TODO// Differentiate behaviour based on errno?
		perror ("Failed to receive command");
		return 0;
	}
	if (cmd->cmd.pio_ancil_type == ANCIL_TYPE_SOCKET) {
			if (cmd->passfd == -1) {
				//WRONG: no support for sockets
				//HANDLE winsock = (HANDLE) WSASocket(FROM_PROTOCOL_INFO, FROM_PROTOCOL_INFO, FROM_PROTOCOL_INFO, &cmd->cmd.pio_ancil_data.pioa_socket, 0, 0);
				//cmd->passfd = cygwin_attach_handle_to_fd(NULL, -1, winsock, NULL, GENERIC_READ | GENERIC_WRITE);
				//tlog (TLOG_UNIXSOCK, LOG_DEBUG, "Received file descriptor as %d, winsock = %d\n", cmd->passfd, winsock);
				cmd->passfd = cygwin_socket_from_protocol_info(&cmd->cmd.pio_ancil_data.pioa_socket);
				tlog (TLOG_UNIXSOCK, LOG_DEBUG, "Received file descriptor as %d\n", cmd->passfd);
			} else {
				//int superfd = (int) WSASocket(FROM_PROTOCOL_INFO, FROM_PROTOCOL_INFO, FROM_PROTOCOL_INFO, &cmd->cmd.pio_ancil_data.pioa_socket, 0, 0);
				//tlog (TLOG_UNIXSOCK, LOG_ERR, "Received superfluous file descriptor as %d", superfd);
				//close (superfd);
			}
	}
	return 1;
}
#endif /* __CYGWIN__ */


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
			errcmd->cmd.pio_data.pioc_error.tlserrno = ECONNRESET;
			snprintf (errcmd->cmd.pio_data.pioc_error.message, 127, "Client fd %d closed", clientfd);
printf ("DEBUG: Freeing callback with cbid=%d for clientfd %d\n", i+1, clientfd);
			post_callback (errcmd);
printf ("DEBUG: Freed   callback with cbid=%d for clientfd %d\n", i+1, clientfd);
		}
	}
}


/* Process a command packet that entered on a TLS pool socket
 */
static void process_command (struct command *cmd) {
	tlog (TLOG_UNIXSOCK, LOG_DEBUG, "Processing command 0x%08x", cmd->cmd.pio_cmd);
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
			send_error (cmd, EACCES, "The STARTTLS facility is disabled in the TLS Pool configuration");
		}
		return;
	case PIOC_CONTROL_DETACH_V2:
		ctlkey_detach (cmd);
		return;
	case PIOC_CONTROL_REATTACH_V2:
		ctlkey_reattach (cmd);
		return;
	case PIOC_PINENTRY_V2:
		register_pinentry_command (cmd);
		return;
	case PIOC_LIDENTRY_REGISTER_V2:
		register_lidentry_command (cmd);
		return;
	default:
		send_error (cmd, ENOSYS, "Command not implemented");
		return;
	}
}


/* Pickup on activity and process it.  Processing may mean a number of things:
 *  - to try an accept() on a server socket (ignoring it upon EAGAIN)
 *  - to trigger a thread that is hoping writing after EAGAIN
 *  - to read a message and further process it
 */
void process_activity (pool_handle_t sox, int soxidx, struct soxinfo *soxi, short int revents) {
	if (revents & POLLOUT) {
		//TODO// signal waiting thread that it may continue
		tlog (TLOG_UNIXSOCK, LOG_CRIT, "Eekk!!  Could send a packet?!?  Unregistering client");
		unregister_client_socket_byindex (soxidx);
		tlspool_close_poolhandle (sox);
	}
	if (revents & POLLIN) {
		if (soxi->flags & SOF_SERVER) {
			struct sockaddr sa;
			socklen_t salen = sizeof (sa);
			pool_handle_t newsox = accept (sox, &sa, &salen);
			if (newsox != INVALID_POOL_HANDLE) {
				tlog (TLOG_UNIXSOCK, LOG_NOTICE, "Received incoming connection.  Registering it");
				register_client_socket (newsox);
			}
		}
		if (soxi->flags & SOF_CLIENT) {
			struct command *cmd = allocate_command_for_clientfd (sox);
			if (receive_command (sox, cmd)) {
				process_command (cmd);
			} else {
				tlog (TLOG_UNIXSOCK, LOG_ERR, "Failed to receive command request");
			}
		}
	}
}

/* Request orderly hangup of the service.
 */
void hangup_service (void) {
	stop_service = 1;
	tlog (TLOG_UNIXSOCK, LOG_NOTICE, "Requested service to hangup soon");
}

#ifdef __CYGWIN__
// CompletedWriteRoutine(DWORD, DWORD, LPOVERLAPPED)
// This routine is called as a completion routine after writing to
// the pipe, or when a new client has connected to a pipe instance.
// It starts another read operation.

VOID WINAPI CompletedWriteRoutine(DWORD dwErr, DWORD cbWritten,
	LPOVERLAPPED lpOverLap)
{
	LPPIPEINST lpPipeInst;
	BOOL fRead = FALSE;

	// lpOverlap points to storage for this instance.

	lpPipeInst = (LPPIPEINST)lpOverLap;

	// The write operation has finished, so read the next request (if
	// there is no error).

	if ((dwErr == 0) && (cbWritten == lpPipeInst->cbToWrite))
		fRead = ReadFileEx(
			lpPipeInst->hPipeInst,
			&lpPipeInst->chRequest,
			sizeof(struct tlspool_command),
			(LPOVERLAPPED)lpPipeInst,
			(LPOVERLAPPED_COMPLETION_ROUTINE)CompletedReadRoutine);

	// Disconnect if an error occurred.

	if (!fRead)
		DisconnectAndClose(lpPipeInst);
}

// CompletedReadRoutine(DWORD, DWORD, LPOVERLAPPED)
// This routine is called as an I/O completion routine after reading
// a request from the client. It gets data and writes it to the pipe.

VOID WINAPI CompletedReadRoutine(DWORD dwErr, DWORD cbBytesRead,
	LPOVERLAPPED lpOverLap)
{
	LPPIPEINST lpPipeInst;
	BOOL fWrite = FALSE;

	// lpOverlap points to storage for this instance.

	lpPipeInst = (LPPIPEINST)lpOverLap;

	// The read operation has finished, so write a response (if no
	// error occurred).

	if ((dwErr == 0) && (cbBytesRead != 0))
	{
		GetAnswerToRequest(lpPipeInst);

		fWrite = WriteFileEx(
			lpPipeInst->hPipeInst,
			&lpPipeInst->chRequest,
			lpPipeInst->cbToWrite,
			(LPOVERLAPPED)lpPipeInst,
			(LPOVERLAPPED_COMPLETION_ROUTINE)CompletedWriteRoutine);
	}

	// Disconnect if an error occurred.

	if (!fWrite)
		DisconnectAndClose(lpPipeInst);
}

// DisconnectAndClose(LPPIPEINST)
// This routine is called when an error occurs or the client closes
// its handle to the pipe.

VOID DisconnectAndClose(LPPIPEINST lpPipeInst)
{
	// Disconnect the pipe instance.

	if (!DisconnectNamedPipe(lpPipeInst->hPipeInst))
	{
		printf("DisconnectNamedPipe failed with %d.\n", GetLastError());
	}

	// Close the handle to the pipe instance.

	CloseHandle(lpPipeInst->hPipeInst);

	// Release the storage for the pipe instance.

	if (lpPipeInst != NULL)
		GlobalFree(lpPipeInst);
}

// CreateAndConnectInstance(LPOVERLAPPED)
// This function creates a pipe instance and connects to the client.
// It returns TRUE if the connect operation is pending, and FALSE if
// the connection has been completed.

BOOL CreateAndConnectInstance(LPOVERLAPPED lpoOverlap)
{
	hPipe = CreateNamedPipe(
		szPipename,               // pipe name
		PIPE_ACCESS_DUPLEX |      // read/write access
		FILE_FLAG_OVERLAPPED,     // overlapped mode
		PIPE_TYPE_MESSAGE |       // message-type pipe
		PIPE_READMODE_MESSAGE |   // message read mode
		PIPE_WAIT,                // blocking mode
		PIPE_UNLIMITED_INSTANCES, // unlimited instances
		BUFSIZE*sizeof(TCHAR),    // output buffer size
		BUFSIZE*sizeof(TCHAR),    // input buffer size
		PIPE_TIMEOUT,             // client time-out
		NULL);                    // default security attributes
	if (hPipe == INVALID_HANDLE_VALUE)
	{
		printf("CreateNamedPipe failed with %d.\n", GetLastError());
		return 0;
	}

	// Call a subroutine to connect to the new client.

	return ConnectToNewClient(hPipe, lpoOverlap);
}

BOOL ConnectToNewClient(HANDLE hPipe, LPOVERLAPPED lpo)
{
	BOOL fConnected, fPendingIO = FALSE;

	// Start an overlapped connection for this pipe instance.
	fConnected = ConnectNamedPipe(hPipe, lpo);

	// Overlapped ConnectNamedPipe should return zero.
	if (fConnected)
	{
		printf("ConnectNamedPipe failed with %d.\n", GetLastError());
		return 0;
	}

	switch (GetLastError())
	{
		// The overlapped connection in progress.
	case ERROR_IO_PENDING:
		fPendingIO = TRUE;
		break;

		// Client is already connected, so signal an event.

	case ERROR_PIPE_CONNECTED:
		if (SetEvent(lpo->hEvent))
			break;

		// If an error occurs during the connect operation...
	default:
		printf("ConnectNamedPipe failed with %d.\n", GetLastError());
		return 0;
	}
	return fPendingIO;
}

VOID GetAnswerToRequest(LPPIPEINST pipe)
{
	//_tprintf(TEXT("[%ld] %s\n"), (long) pipe->hPipeInst, pipe->chRequest);
	////StringCchCopy(pipe->chReply, BUFSIZE, TEXT("Default answer from server"));
	//strcpy(pipe->chReply, TEXT("Default answer from server"));
	//pipe->cbToWrite = (lstrlen(pipe->chReply) + 1)*sizeof(TCHAR);
	
	
	union pio_data *d = &pipe->chRequest.pio_data;
	strcpy (d->pioc_ping.YYYYMMDD_producer, TLSPOOL_IDENTITY_V2);
	d->pioc_ping.facilities &= facilities;
	pipe->cbToWrite = sizeof (struct tlspool_command);
	printf("hallo %d\n", d->pioc_ping.facilities);
}
#endif /* __CYGWIN__ */

/* The main service loop.  It uses poll() to find things to act upon. */
void run_service (void) {
#ifdef __CYGWIN__
	HANDLE hConnectEvent;
	OVERLAPPED oConnect;
	LPPIPEINST lpPipeInst;
	DWORD dwWait, cbRet;
	BOOL fSuccess, fPendingIO;

	// Create one event object for the connect operation.

	hConnectEvent = CreateEvent(
		NULL,    // default security attribute
		TRUE,    // manual reset event
		TRUE,    // initial state = signaled
		NULL);   // unnamed event object

	if (hConnectEvent == NULL)
	{
		printf("CreateEvent failed with %d.\n", GetLastError());
		return;
	}

	oConnect.hEvent = hConnectEvent;

	// Call a subroutine to create one instance, and wait for
	// the client to connect.

	fPendingIO = CreateAndConnectInstance(&oConnect);

	while (1)
	{
		// Wait for a client to connect, or for a read or write
		// operation to be completed, which causes a completion
		// routine to be queued for execution.

		dwWait = WaitForSingleObjectEx(
			hConnectEvent,  // event object to wait for
			INFINITE,       // waits indefinitely
			TRUE);          // alertable wait enabled

		switch (dwWait)
		{
			// The wait conditions are satisfied by a completed connect
			// operation.
		case 0:
			// If an operation is pending, get the result of the
			// connect operation.

			if (fPendingIO)
			{
				fSuccess = GetOverlappedResult(
					hPipe,     // pipe handle
					&oConnect, // OVERLAPPED structure
					&cbRet,    // bytes transferred
					FALSE);    // does not wait
				if (!fSuccess)
				{
					printf("ConnectNamedPipe (%d)\n", GetLastError());
					return;
				}
			}

			// Allocate storage for this instance.

			lpPipeInst = (LPPIPEINST)GlobalAlloc(
				GPTR, sizeof(PIPEINST));
			if (lpPipeInst == NULL)
			{
				printf("GlobalAlloc failed (%d)\n", GetLastError());
				return;
			}

			lpPipeInst->hPipeInst = hPipe;

			// Start the read operation for this client.
			// Note that this same routine is later used as a
			// completion routine after a write operation.

			lpPipeInst->cbToWrite = 0;
			CompletedWriteRoutine(0, 0, (LPOVERLAPPED)lpPipeInst);

			// Create new pipe instance for the next client.

			fPendingIO = CreateAndConnectInstance(
				&oConnect);
			break;

			// The wait is satisfied by a completed read or write
			// operation. This allows the system to execute the
			// completion routine.

		case WAIT_IO_COMPLETION:
			break;

			// An error occurred in the wait function.

		default:
			printf("WaitForSingleObjectEx (%d)\n", GetLastError());
			return;
		}
	}
#else /* __CYGWIN__ */
	int i;
	int polled;
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
	tlog (TLOG_UNIXSOCK, LOG_DEBUG, "Polling %d sockets numbered %d, %d, %d, ...", num_sox, soxpoll [0].fd, soxpoll [1].fd, soxpoll [2].fd);
	while (polled = poll (soxpoll, num_sox, -1), polled > 0) {
		tlog (TLOG_UNIXSOCK, LOG_DEBUG, "Polled %d sockets, returned %d", num_sox, polled);
		for (i=0; i<num_sox; i++) {
			if (soxpoll [i].revents & (POLLHUP|POLLERR|POLLNVAL)) {
				pool_handle_t sox = soxpoll [i].fd;
				tlog (TLOG_UNIXSOCK, LOG_NOTICE, "Unregistering socket %d", sox);
				unregister_client_socket_byindex (i);
				close (sox);
				continue;
			} else if (soxpoll [i].revents) {
				tlog (TLOG_UNIXSOCK, LOG_DEBUG, "Socket %d has revents=%d", soxpoll [i].fd, soxpoll [i].revents);
				process_activity (soxpoll [i].fd, i, &soxinfo [i], soxpoll [i].revents);
			}
		}
		tlog (TLOG_UNIXSOCK, LOG_DEBUG, "Polling %d sockets numbered %d, %d, %d, ...", num_sox, soxpoll [0].fd, soxpoll [1].fd, soxpoll [2].fd);
	}
	if (stop_service) {
		tlog (TLOG_UNIXSOCK, LOG_NOTICE, "Service hangup in response to request");
	} else {
		tlog (TLOG_UNIXSOCK, LOG_DEBUG, "Polled %d sockets, returned %d", num_sox, polled);
		perror ("Failed to poll for activity");
	}
#endif /* __CYGWIN__ */
}
