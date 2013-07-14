/* tlspool/service.c -- TLS pool service, socket handling, command dispatcher */

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <pthread.h>

#include <fcntl.h>
#include <poll.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <tlspool/commands.h>
#include <tlspool/internal.h>


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

static struct callback cblist [1024];
static struct callback *cbfree;
static pthread_mutex_t cbfree_mutex = PTHREAD_MUTEX_INITIALIZER;


/* Register a socket.  It is assumed that first all server sockets register */
void register_socket (int sox, uint32_t soxinfo_flags) {
	int flags = fcntl (sox, F_GETFD);
	flags |= O_NONBLOCK;
	fcntl (sox, F_SETFD, flags);
	//TODO// if (soxinfo == NULL) {
	//TODO// 	soxinfo = calloc ()
	//TODO// }
	if (num_sox == 1024) {
		fprintf (stderr, "Cannot allocate more than 1024 server sockets\n");
		exit (1);
	}
	soxpoll [num_sox].fd = sox;
	soxpoll [num_sox].events = POLLIN;
	soxpoll [num_sox].revents = 0;
	soxinfo [num_sox].flags = soxinfo_flags;
	soxinfo [num_sox].cbq = NULL;
	num_sox++;
}


void register_server_socket (int srvsox) {
	register_socket (srvsox, SOF_SERVER);
}


void register_client_socket (int clisox) {
	register_socket (clisox, SOF_CLIENT);
}


/* TODO: This may copy information back and thereby avoid processing in the
 * current loop passthrough.  No problem, poll() will show it once more. */
static void unregister_client_socket_byindex (int soxidx) {
	num_sox--;
	if (soxidx < num_sox) {
		memcpy (&soxinfo [soxidx], &soxinfo [num_sox], sizeof (*soxinfo));
		memcpy (&soxpoll [soxidx], &soxpoll [num_sox], sizeof (*soxpoll));
	}
}


int send_command (struct command *cmd, int passfd) {
	int newfd;
	char anc [CMSG_SPACE(sizeof (int))];
	struct iovec iov;
	struct msghdr mh = { 0 };
	struct cmsghdr *cmsg;

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
		* (int *) CMSG_DATA (cmsg) = cmd->passfd;
	}

	printf ("DEBUG: Sending command 0x%08x to socket %d\n", cmd->cmd.pio_cmd, cmd->clientfd);
	if (sendmsg (cmd->clientfd, &mh, 0) == -1) {
		//TODO// Differentiate behaviour based on errno?
		perror ("Failed to send command");
		return 0;
	} else {
		printf ("DEBUG: Sent command code 0x%08x\n", cmd->cmd.pio_cmd);
	}
}


/* Report an error response to the user.  Report with the given errno and msg.
 * Note that this function does not terminate actions, but it should be the
 * last response to the client.
 */
void send_error (struct command *cmd, int tlserrno, char *msg) {
	cmd->cmd.pio_cmd = PIOC_ERROR_V1;
	cmd->cmd.pio_cbid = 0;
	cmd->cmd.pio_data.pioc_error.tlserrno = tlserrno;
	strncpy (cmd->cmd.pio_data.pioc_error.message, msg, sizeof (cmd->cmd.pio_data.pioc_error.message));
	if (!send_command (cmd, -1)) {
		perror ("Failed to send error reply");
	}
}


/* Receive a command.  Return nonzero on success, zero on failure. */
int receive_command (int sox, struct command *cmd) {
	int newfd;
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

	cmd->clientfd = sox;
	cmd->passfd = -1;
	if (recvmsg (sox, &mh, 0) == -1) {
		//TODO// Differentiate behaviour based on errno?
		perror ("Failed to receive command");
		return 0;
	}
	printf ("DEBUG: Received command request code 0x%08x\n", cmd->cmd.pio_cmd);

	cmsg = CMSG_FIRSTHDR (&mh);
	if (cmsg && (cmsg->cmsg_len == CMSG_LEN (sizeof (int)))) {
		if ((cmsg->cmsg_level == SOL_SOCKET) && (cmsg->cmsg_type == SCM_RIGHTS)) {
			cmd->passfd = * (int *) CMSG_DATA (cmsg);
			printf ("DEBUG: Received file descriptor as %d\n", cmd->passfd);
		}
	}

	return 1;
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
	if (cblist [cbid].fd < 0) {
		return 0;
	}
	if (cblist [cbid].fd != cmd->clientfd) {
		return 0;
	}
	if (!cblist [cbid].followup) {
		return 0;
	}
	return 1;
}


/* Desire a callback and in the process of doing so, send a callback response.
 * This must be called from another thread than the main TLS pool thread.
 */
static void await_callback (struct command *cmdresp, struct command **followup) {
	int cbi;
	pthread_mutex_lock (&cbfree_mutex);
	struct callback *cb = cbfree;
	if (!cb) {
		//TODO// Allocate more...
		fprintf (stderr, "Ran out of callback structures.  Crashing as a coward\n");
		exit (1);
	}
	cbfree = cb->next;
	pthread_mutex_unlock (&cbfree_mutex);
	cmdresp->cmd.pio_cbid = (((intptr_t) cb) - ((intptr_t) cblist)) / ((intptr_t) sizeof (struct callback));
	cb->fd = cmdresp->clientfd;
	cb->followup = followup;
	cb->next = NULL; //TODO// Enqueu in fd-queue
	//TODO// race condition: should send after locking the mutex...
	send_command (cmdresp, -1);
	pthread_mutex_lock (&cb->lock);
}


/* Present a callback command request to the thread that is waiting for it.
 * This must be called from the main thread of the TLS pool, and it will
 * spark life to the thread that is awaiting the callback.
 */
static void post_callback (struct command *cmd) {
	uint16_t cbid = cmd->cmd.pio_cbid - 1;
	cblist [cbid].fd = -1;
	* cblist [cbid].followup = cmd;
	pthread_mutex_unlock (&cblist [cbid].lock);
	pthread_mutex_lock (&cbfree_mutex);
	//TODO// Remove cblist [cbid] from the fd's cblist
	cblist [cbid].next = cbfree;
	cbfree = &cblist [cbid];
	pthread_mutex_unlock (&cbfree_mutex);
}


/* Process a command packet that entered on a TLS pool socket
 */
static void process_command (struct command *cmd) {
	printf ("DEBUG: Processing command 0x%08x\n", cmd->cmd.pio_cmd);
	union pio_data *d = &cmd->cmd.pio_data;
	int iscb = is_callback (cmd);
	if (iscb) {
		post_callback (cmd);
		return;
	}
	switch (cmd->cmd.pio_cmd) {
	case PIOC_PING_V1:
		strcpy (d->pioc_ping.YYYYMMDD_producer, TLSPOOL_IDENTITY_V1);
		send_command (cmd, -1);
		return;
	case PIOC_STARTTLS_CLIENT_V1:
		starttls_client (cmd);
		return;
	case PIOC_STARTTLS_SERVER_V1:
		starttls_server (cmd);
		return;
	case PIOC_PINENTRY_V1:
		register_pinentry_command (cmd);
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
void process_activity (int sox, int soxidx, struct soxinfo *soxi, short int revents) {
	if (revents & POLLOUT) {
		//TODO// signal waiting thread that it may continue
		printf ("DEBUG: Eekk!!  Could send a packet?!?  Unregistering client\n");
		unregister_client_socket_byindex (soxidx);
		close (sox);
	}
	if (revents & POLLIN) {
		if (soxi->flags & SOF_SERVER) {
			struct sockaddr sa;
			socklen_t salen = sizeof (sa);
			int newsox = accept (sox, &sa, &salen);
			if (newsox != -1) {
				printf ("DEBUG: Received incoming connection.  Registering it.\n");
				register_client_socket (newsox);
			}
		}
		if (soxi->flags & SOF_CLIENT) {
			struct command cmd;
			if (receive_command (sox, &cmd)) {
				process_command (&cmd);
			} else {
				printf ("DEBUG: Failed to receive command request\n");
			}
		}
	}
}

/* The main service loop.  It uses poll() to find things to act upon. */
void run_service (void) {
	int i;
	int polled;
	cbfree = NULL;
	for (i=0; i<1024; i++) {
		cblist [i].next = cbfree;
		cblist [i].fd = -1; // Mark as unused
		pthread_mutex_init (&cblist [i].lock, NULL);
		pthread_mutex_lock (&cblist [i].lock);
		cblist [i].followup = NULL;
		cbfree = &cblist [i];
	}
	printf ("DEBUG: Polling %d sockets numbered %d, %d, %d, ...\n", num_sox, soxpoll [0].fd, soxpoll [1].fd, soxpoll [2].fd);
	while (polled = poll (soxpoll, num_sox, -1), polled > 0) {
		printf ("DEBUG: Polled %d sockets, returned %d\n", num_sox, polled);
		for (i=0; i<num_sox; i++) {
			if (soxpoll [i].revents & (POLLHUP|POLLERR|POLLNVAL)) {
				int sox = soxpoll [i].fd;
				printf ("DEBUG: Unregistering socket %d\n", sox);
				unregister_client_socket_byindex (i);
				close (sox);
				continue;
			} else if (soxpoll [i].revents) {
				printf ("DEBUG: Socket %d has revents=%d\n", soxpoll [i].fd, soxpoll [i].revents);
				process_activity (soxpoll [i].fd, i, &soxinfo [i], soxpoll [i].revents);
			}
		}
		printf ("DEBUG: Polling %d sockets numbered %d, %d, %d, ...\n", num_sox, soxpoll [0].fd, soxpoll [1].fd, soxpoll [2].fd);
	}
	printf ("DEBUG: Polled %d sockets, returned %d\n", num_sox, polled);
	perror ("Failed to poll for activity");
	exit (1);
}

