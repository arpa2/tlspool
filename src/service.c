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

#define PIPE_TIMEOUT 5000
#define BUFSIZE 4096

#define _tprintf printf
#define _tmain main
#endif /* WINDOWS_PORT */

#ifdef WINDOWS_PORT
extern char szPipename[1024];
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


/* Register a socket.  It is assumed that first all server sockets register */
void register_socket (pool_handle_t sox, uint32_t soxinfo_flags) {
#ifndef WINDOWS_PORT
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
#endif /* !WINDOWS_PORT */
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
#ifndef WINDOWS_PORT
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
#endif /* !WINDOWS_PORT */
}
#ifdef WINDOWS_PORT
#define CONNECTING_STATE 0
#define READING_STATE 1
#define INSTANCES 4
#define PIPE_TIMEOUT 5000
#define BUFSIZE 4096

VOID DisconnectAndReconnect(DWORD);
BOOL ConnectToNewClient(HANDLE, LPOVERLAPPED);
void copy_tls_command(struct command *cmd, struct tlspool_command *tls_command);
static void process_command (struct command *cmd);

PIPEINST Pipe[INSTANCES];
HANDLE hEvents[INSTANCES];

#if defined(WINDOWS_PORT)
static int socket_from_protocol_info (LPWSAPROTOCOL_INFOW lpProtocolInfo)
{
	return WSASocketW (FROM_PROTOCOL_INFO, FROM_PROTOCOL_INFO, FROM_PROTOCOL_INFO, lpProtocolInfo, 0, 0); 
}
#endif

static int create_named_pipes (LPCTSTR lpszPipename)
{
   DWORD i, dwWait, cbRet, dwErr;
   BOOL fSuccess;
// The initial loop creates several instances of a named pipe
// along with an event object for each instance.  An
// overlapped ConnectNamedPipe operation is started for
// each instance.

   for (i = 0; i < INSTANCES; i++)
   {

   // Create an event object for this instance.

      hEvents[i] = CreateEvent(
         NULL,    // default security attribute
         TRUE,    // manual-reset event
         TRUE,    // initial state = signaled
         NULL);   // unnamed event object

      if (hEvents[i] == NULL)
      {
         printf("CreateEvent failed with %d.\n", GetLastError());
         return 0;
      }

      Pipe[i].oOverlap.hEvent = hEvents[i];

      Pipe[i].hPipeInst = CreateNamedPipe(
         lpszPipename,            // pipe name
         PIPE_ACCESS_DUPLEX |     // read/write access
         FILE_FLAG_OVERLAPPED,    // overlapped mode
         PIPE_TYPE_MESSAGE |      // message-type pipe
         PIPE_READMODE_MESSAGE |  // message-read mode
         PIPE_WAIT,               // blocking mode
         INSTANCES,               // number of instances
         BUFSIZE*sizeof(TCHAR),   // output buffer size
         BUFSIZE*sizeof(TCHAR),   // input buffer size
         PIPE_TIMEOUT,            // client time-out
         NULL);                   // default security attributes

      if (Pipe[i].hPipeInst == INVALID_HANDLE_VALUE)
      {
         printf("CreateNamedPipe failed with %d.\n", GetLastError());
         return 0;
      }

   // Call the subroutine to connect to the new client

      Pipe[i].fPendingIO = ConnectToNewClient(
         Pipe[i].hPipeInst,
         &Pipe[i].oOverlap);

      Pipe[i].dwState = Pipe[i].fPendingIO ?
         CONNECTING_STATE : // still connecting
         READING_STATE;     // ready to read
   }

   while (1)
   {
   // Wait for the event object to be signaled, indicating
   // completion of an overlapped read, write, or
   // connect operation.

      dwWait = WaitForMultipleObjects(
         INSTANCES,    // number of event objects
         hEvents,      // array of event objects
         FALSE,        // does not wait for all
         INFINITE);    // waits indefinitely

   // dwWait shows which pipe completed the operation.

      i = dwWait - WAIT_OBJECT_0;  // determines which pipe
      if (i < 0 || i > (INSTANCES - 1))
      {
         printf("Index out of range.\n");
         return 0;
      }

   // Get the result if the operation was pending.

      if (Pipe[i].fPendingIO)
      {
         fSuccess = GetOverlappedResult(
            Pipe[i].hPipeInst, // handle to pipe
            &Pipe[i].oOverlap, // OVERLAPPED structure
            &cbRet,            // bytes transferred
            FALSE);            // do not wait

         switch (Pipe[i].dwState)
         {
         // Pending connect operation
            case CONNECTING_STATE:
               if (! fSuccess)
               {
                   printf("Error %d.\n", GetLastError());
                   return 0;
               }
               printf("Connected.\n");
               Pipe[i].dwState = READING_STATE;
               break;

         // Pending read operation
            case READING_STATE:
               if (! fSuccess || cbRet == 0)
               {
                  printf("Error fSuccess = %d, cbRet = %d.\n", fSuccess, cbRet);
                  DisconnectAndReconnect(i);
                  continue;
               }
               printf("OK cbRet = %d.\n", cbRet);
               Pipe[i].cbRead = cbRet;
				struct command *cmd = allocate_command_for_clientfd (&Pipe[i]);
				Pipe[i].chRequest.hPipe = Pipe[i].hPipeInst;
				copy_tls_command (cmd, &Pipe[i].chRequest);
				if (cmd->cmd.pio_ancil_type == ANCIL_TYPE_SOCKET) {
					if (cmd->passfd == -1) {
						//WRONG: no support for sockets
						//HANDLE winsock = (HANDLE) WSASocket(FROM_PROTOCOL_INFO, FROM_PROTOCOL_INFO, FROM_PROTOCOL_INFO, &cmd->cmd.pio_ancil_data.pioa_socket, 0, 0);
						//cmd->passfd = cygwin_attach_handle_to_fd(NULL, -1, winsock, NULL, GENERIC_READ | GENERIC_WRITE);
						//tlog (TLOG_UNIXSOCK, LOG_DEBUG, "Received file descriptor as %d, winsock = %d\n", cmd->passfd, winsock);
						cmd->passfd = socket_from_protocol_info(&cmd->cmd.pio_ancil_data.pioa_socket);
if (cmd->passfd == -1) printf("WSAGetLastError(void) = %d\n", WSAGetLastError());
						tlog (TLOG_UNIXSOCK, LOG_DEBUG, "Received file descriptor as %d\n", cmd->passfd);
					} else {
						//int superfd = (int) WSASocket(FROM_PROTOCOL_INFO, FROM_PROTOCOL_INFO, FROM_PROTOCOL_INFO, &cmd->cmd.pio_ancil_data.pioa_socket, 0, 0);
						//tlog (TLOG_UNIXSOCK, LOG_ERR, "Received superfluous file descriptor as %d", superfd);
						//close (superfd);
					}
				}
				process_command (cmd);

               break;

            default:
            {
               printf("Invalid pipe state.\n");
               return 0;
            }
         }
      }

   // The pipe state determines which operation to do next.

      switch (Pipe[i].dwState)
      {
      // READING_STATE:
      // The pipe instance is connected to the client
      // and is ready to read a request from the client.

         case READING_STATE:
            fSuccess = ReadFile(
               Pipe[i].hPipeInst,
               &Pipe[i].chRequest,
               sizeof (Pipe[i].chRequest),
               &Pipe[i].cbRead,
               &Pipe[i].oOverlap);

         // The read operation completed successfully.

            if (fSuccess && Pipe[i].cbRead != 0)
            {
				Pipe[i].fPendingIO = FALSE;

               continue;
            }

         // The read operation is still pending.

            dwErr = GetLastError();
            if (! fSuccess && (dwErr == ERROR_IO_PENDING))
            {
               printf("read pending. %d\n", sizeof (Pipe[i].chRequest));
               Pipe[i].fPendingIO = TRUE;
               continue;
            }
            printf("The read failed with %d.\n", GetLastError());

         // An error occurred; disconnect from the client.

            DisconnectAndReconnect(i);
            break;

         default:
         {
            printf("Invalid pipe state.\n");
            return 0;
         }
      }
  }
  return 0;
}


// DisconnectAndReconnect(DWORD)
// This function is called when an error occurs or when the client
// closes its handle to the pipe. Disconnect from this client, then
// call ConnectNamedPipe to wait for another client to connect.

VOID DisconnectAndReconnect(DWORD i)
{
// Disconnect the pipe instance.

   if (! DisconnectNamedPipe(Pipe[i].hPipeInst) )
   {
      printf("DisconnectNamedPipe failed with %d.\n", GetLastError());
   }

// Call a subroutine to connect to the new client.

   Pipe[i].fPendingIO = ConnectToNewClient(
      Pipe[i].hPipeInst,
      &Pipe[i].oOverlap);

   Pipe[i].dwState = Pipe[i].fPendingIO ?
      CONNECTING_STATE : // still connecting
      READING_STATE;     // ready to read
}

// ConnectToNewClient(HANDLE, LPOVERLAPPED)
// This function is called to start an overlapped connect operation.
// It returns TRUE if an operation is pending or FALSE if the
// connection has been completed.

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
      {
         printf("ConnectNamedPipe failed with %d.\n", GetLastError());
         return 0;
      }
   }
   return fPendingIO;
}

static int np_send_command(struct tlspool_command *cmd) {
	DWORD  cbToWrite, cbWritten;
	OVERLAPPED overlapped;
	BOOL fSuccess;

	/* Send the request */
	// Send a message to the pipe server.

	cbToWrite = sizeof (struct tlspool_command);
	_tprintf(TEXT("Sending %d byte cmd\n"), cbToWrite);

	memset(&overlapped, 0, sizeof(overlapped));
	overlapped.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);

	fSuccess = WriteFile(
		cmd->hPipe,                  // pipe handle
		cmd,                    // cmd message
		cbToWrite,              // cmd message length
		NULL,                  // bytes written
		&overlapped);            // overlapped

	if (!fSuccess && GetLastError() == ERROR_IO_PENDING )
	{
printf ("DEBUG: Write I/O pending\n");
		fSuccess = WaitForSingleObject(overlapped.hEvent, INFINITE) == WAIT_OBJECT_0;
	}

	if (fSuccess) {
		fSuccess = GetOverlappedResult(cmd->hPipe, &overlapped, &cbWritten, TRUE);
	}

	if (!fSuccess)
	{
		_tprintf(TEXT("WriteFile to pipe failed. GLE=%d\n"), GetLastError());
		errno = EPIPE;
		return -1;
	} else {
printf ("DEBUG: Wrote %ld bytes to pipe\n", cbWritten);
	}
printf("DEBUG: Message sent to server, receiving reply as follows:\n");
	return 0;
}
#endif /* WINDOWS_PORT */

int send_command (struct command *cmd, int passfd) {
#ifdef WINDOWS_PORT
	cmd->cmd.pio_ancil_type = ANCIL_TYPE_NONE;
	memset (&cmd->cmd.pio_ancil_data,
			0,
			sizeof (cmd->cmd.pio_ancil_data));
	return !np_send_command(&cmd->cmd) ? 1 : 0;
#else /* WINDOWS_PORT */
	char anc [CMSG_SPACE(sizeof (int))];
	struct iovec iov;
	struct msghdr mh;
	struct cmsghdr *cmsg;

	if (cmd == NULL) {
		return 1;	// Success guaranteed when nobody is listening
	}
	assert (passfd == -1);	// Working passfd code retained but not used
	memset (anc, 0, sizeof (anc));
	memset (&iov, 0, sizeof (iov));
	memset (&mh, 0, sizeof (mh));
	iov.iov_base = &cmd->cmd;
	iov.iov_len = sizeof (cmd->cmd);
	mh.msg_iov = &iov;
	mh.msg_iovlen = 1;
	if (passfd >= 0) {
		mh.msg_control = anc;
		mh.msg_controllen = sizeof (anc);
		cmsg = CMSG_FIRSTHDR (&mh);
		cmsg->cmsg_level = SOL_SOCKET;
		cmsg->cmsg_type = SCM_RIGHTS;
		cmsg->cmsg_len = CMSG_LEN (sizeof (int));
		* (int *) CMSG_DATA (cmsg) = passfd;
	}
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
#endif /* WINDOWS_PORT */
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


#ifndef WINDOWS_PORT
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
#endif /* !WINDOWS_PORT */

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


/* Pickup on activity and process it.  Processing may mean a number of things:
 *  - to try an accept() on a server socket (ignoring it upon EAGAIN)
 *  - to trigger a thread that is hoping writing after EAGAIN
 *  - to read a message and further process it
 */
#ifndef WINDOWS_PORT
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
#endif

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
#ifdef WINDOWS_PORT
	create_named_pipes ((LPCTSTR) szPipename);
#else /* WINDOWS_PORT */
	int polled;
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
#endif /* WINDOWS_PORT */
}
