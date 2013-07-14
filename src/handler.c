/* tlspool/handler.c -- Setup and validation handler for TLS session */


#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <pthread.h>

#include <unistd.h>
#include <errno.h>
#include <poll.h>

#include <sys/types.h>
#include <sys/socket.h>

#include <gnutls/gnutls.h>

#include <tlspool/internal.h>


/* This module hosts TLS handlers which treat an individual connection.
 *
 * Initially, the TLS setup is processed, which means validating the
 * connection.  If and when this succeeds, a continued process is needed
 * to encrypt and decrypt traffic while it is in transit.
 *
 * Every TLS connection (including the attempt to set it up) is hosted in
 * its own thread.  This means that it can abide time to wait for PINENTRY
 * or LOCALID responses.  It also means a very clear flow when the time
 * comes to destroy a connection.
 *
 * While encrypting and decrypting traffic passing through, the thread
 * will use its own poll() call, and thus offload the potentially large
 * one of the main thread, which is supposed to be a low-traffic task.
 * The set of file descriptors used by the session-handler threads are
 * in contrast very small and can easily be started for every single
 * packet passing through.
 *
 * Might the user terminate a process while this one is waiting for a
 * callback command request, then the main TLS pool thread will take
 * care of taking down this thread.  To that end, it sets the followup
 * pointer that normally holds a callback response to NULL, and then
 * permits this thread to run again.  This will lead to a shutdown of
 * this process, and proper closing of all connections.  The remote peer
 * will therefore see the result of a local kill as a connection reset.
 *
 * In case one of the end points of the connection is terminated, a
 * similar thing will happen; the thread will terminate itself after
 * a cleanup of any outstanding resources.  This, once again, leads
 * to passing on the reset of a connection between the encrypted and
 * side of the connection.
 */


/*
 * The copycat function is a bidirectional transport between the given
 * remote and local sockets, but it will encrypt traffic from local to
 * remote, and decrypt traffic from remote to local.  It will do this
 * until one of the end points is shut down, at which time it will
 * return and assume the context will close down both pre-existing
 * sockets.
 * TODO: Also detect & handle close-down of the controling clientfd?
 */
static void copycat (int remote, int local, int master) {
	char buf [1024];
	struct pollfd inout [3];
	ssize_t sz;
	inout [0].fd = local;
	inout [1].fd = remote;
	inout [2].fd = master;
	inout [0].events = inout [1].events = POLLIN;
	inout [2].events = 0;	// error events only
	printf ("DEBUG: Starting copycat cycle for local=%d, remote=%d\n", local, remote);
	while (1) {
		if (poll (inout, 3, -1) == -1) {
			printf ("DEBUG: Copycat polling returned an error\n");
			break;	// Polling sees an error
		}
		if ((inout [0].revents | inout [1].revents | inout [2].revents) & ~POLLIN) {
			printf ("DEBUG: Copycat polling returned a special condition\n");
			break;	// Apparently, one of POLLERR, POLLHUP, POLLNVAL
		}
		if (inout [0].revents & POLLIN) {
			// Read local and encrypt to remote
			sz = recv (local, buf, sizeof (buf), MSG_DONTWAIT);
			printf ("DEBUG: Copycat received %d local bytes\n", (int) sz);
			if (sz == -1) {
				break;	// stream error
			} else if (sz == 0) {
				errno = 0;
				break;	// orderly shutdown
			} else if (send (remote, buf, sz, MSG_DONTWAIT) != sz) {
				break;	// communication error
			}
		}
		if (inout [1].revents & POLLIN) {
			// Read remote and decrypt to local
			sz = recv (remote, buf, sizeof (buf), MSG_DONTWAIT);
			printf ("DEBUG: Copycat received %d remote bytes\n", (int) sz);
			if (sz == -1) {
				break;	// stream error
			} else if (sz == 0) {
				errno = 0;
				break;	// orderly shutdown
			} else if (send (local, buf, sz, MSG_DONTWAIT) != sz) {
				break;	// communication error
			}
		}
	}
	printf ("DEBUG: Ending copycat cycle for local=%d, remote=%d\n", local, remote);
}


/*
 * The starttls_task is a main program for the setup of a TLS connection,
 * either in client mode or server mode.  Note that the distinction between
 * client and server mode is only a TLS concern, but not of interest to the
 * application or the records exchanged.
 *
 * If the STARTTLS operation succeeds, this will be reported back to the
 * application, but the TLS pool will continue to be active in a copycat
 * procedure: encrypting outgoing traffic and decrypting incoming traffic.
 * TODO: Are client and server routines different?
 *
 * The thread is started with an ownership lock on the provided cmd.
 * It should unlock it as soon as possible, and the parent thread waits
 * for this before giving up on cmd.
 */
static void *starttls_thread (void *cmd_void) {
	struct command *cmd = (struct command *) cmd_void;
	int soxx [2];	// Plaintext stream between TLS pool and application
	int passfd = cmd->passfd;
	int clientfd = cmd->clientfd;
	//TODO// Distinguish between client and server through cmd
	//TODO// Actually do STARTTLS ;-)
	if (passfd == -1) {
		send_error (cmd, EPROTO, "You must supply a socket");
		pthread_mutex_unlock (&cmd->ownership);
		return;
	}
	if (socketpair (SOCK_STREAM, AF_UNIX, 0, soxx) < 0) {
		send_error (cmd, errno, "Failed to create 2ary sockets");
		pthread_mutex_unlock (&cmd->ownership);
		return;
	}
	cmd->cmd.pio_data.pioc_starttls.localid [0] =
	cmd->cmd.pio_data.pioc_starttls.remoteid [0] = 0;
	send_command (cmd, cmd->clientfd);	 // soxx [0] is app-received
	pthread_mutex_unlock (&cmd->ownership);
	copycat (soxx [1], passfd, clientfd); // soxx [1] is pooled decryptlink
	close (soxx [0]);
	close (soxx [1]);
	close (passfd);
}


/*
 * The starttls_client function responds to an application's request to 
 * setup TLS for a given file descriptor, and return a file descriptor
 * with the unencrypted view when done.  The main thing done here is to
 * spark off a new thread that handles the operations.
 * TODO: Are client and server routines different?
 */
void starttls_client (struct command *cmd) {
	//TODO// Move mutex initialisation to the service code
	pthread_mutex_init (&cmd->ownership, NULL);
	pthread_mutex_lock (&cmd->ownership);
	/* Create a thread and, if successful, wait for it to unlock cmd */
	errno = pthread_create (&cmd->handler, NULL, starttls_thread, (void *) cmd);
	if (errno) {
		send_error (cmd, ESRCH, "STARTTLS_CLIENT thread refused");
		pthread_mutex_unlock (&cmd->ownership);
		return;
	}
	errno = pthread_detach (cmd->handler);
	if (errno) {
		//TODO// Kill the thread... somehow
		send_error (cmd, ESRCH, "STARTTLS_CLIENT thread detachment refused");
		pthread_mutex_lock (&cmd->ownership);
		pthread_mutex_unlock (&cmd->ownership);
		return;
	}
	/* Do not continue before the thread gives up ownership of cmd */
	pthread_mutex_lock (&cmd->ownership);
	pthread_mutex_unlock (&cmd->ownership);
}

/*
 * The starttls_server function responds to an application's request to 
 * setup TLS for a given file descriptor, and return a file descriptor
 * with the unencrypted view when done.  The main thing done here is to
 * spark off a new thread that handles the operations.
 */
void starttls_server (struct command *cmd) {
	//TODO// Move mutex initialisation to the service code
	pthread_mutex_init (&cmd->ownership, NULL);
	pthread_mutex_lock (&cmd->ownership);
	/* Create a thread and, if successful, wait for it to unlock cmd */
	errno = pthread_create (&cmd->handler, NULL, starttls_thread, (void *) cmd);
	if (errno) {
		send_error (cmd, ESRCH, "STARTTLS_SERVER thread refused");
		pthread_mutex_unlock (&cmd->ownership);
		return;
	}
	errno = pthread_detach (cmd->handler);
	if (errno) {
		//TODO// Kill the thread... somehow
		send_error (cmd, ESRCH, "STARTTLS_CLIENT thread detachment refused");
		pthread_mutex_lock (&cmd->ownership);
		pthread_mutex_unlock (&cmd->ownership);
		return;
	}
	/* Do not continue before the thread gives up ownership of cmd */
	pthread_mutex_lock (&cmd->ownership);
	pthread_mutex_unlock (&cmd->ownership);
}

