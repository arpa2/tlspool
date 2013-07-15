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
 * GnuTLS infrastructure setup.  Generate keys and so on.
 */
static gnutls_dh_params_t dh_params;
static gnutls_anon_server_credentials_t srv_anoncred;
static gnutls_anon_client_credentials_t cli_anoncred;


static void generate_dh_params (void)
{
  unsigned int bits = gnutls_sec_param_to_pk_bits (GNUTLS_PK_DH, GNUTLS_SEC_PARAM_LEGACY);
  /* Generate Diffie-Hellman parameters - for use with DHE
   * kx algorithms. These should be discarded and regenerated
   * once a day, once a week or once a month. Depending on the
   * security requirements.
   */
  gnutls_dh_params_init (&dh_params);
  gnutls_dh_params_generate2 (dh_params, bits);
}

void setup_handler (void) {
	gnutls_global_init ();
	gnutls_anon_allocate_server_credentials (&srv_anoncred);
	gnutls_anon_allocate_client_credentials (&cli_anoncred);
	generate_dh_params ();
	gnutls_anon_set_server_dh_params (srv_anoncred, dh_params);
	//NOT_APPLICABLE// gnutls_anon_set_client_dh_params (cli_anoncred, dh_params);
}


/*
 * The copycat function is a bidirectional transport between the given
 * remote and local sockets, but it will encrypt traffic from local to
 * remote, and decrypt traffic from remote to local.  It will do this
 * until one of the end points is shut down, at which time it will
 * return and assume the context will close down both pre-existing
 * sockets.
 */
static void copycat (int local, int remote, gnutls_session_t wrapped, int master) {
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
			printf ("DEBUG: Copycat received %d local bytes from %d\n", (int) sz, local);
			if (sz == -1) {
				break;	// stream error
			} else if (sz == 0) {
				errno = 0;
				break;	// orderly shutdown
			} else if (gnutls_record_send (wrapped, buf, sz) != sz) {
				break;	// communication error
			} else {
				printf ("DEBUG: Copycat sent %d bytes to remote %d\n", (int) sz, remote);
			}
		}
		if (inout [1].revents & POLLIN) {
			// Read remote and decrypt to local
			sz = gnutls_record_recv (wrapped, buf, sizeof (buf));
			printf ("DEBUG: Copycat received %d remote bytes from %d\n", (int) sz, remote);
			if (sz == -1) {
				break;	// stream error
			} else if (sz == 0) {
				errno = 0;
				break;	// orderly shutdown
			} else if (send (local, buf, sz, MSG_DONTWAIT) != sz) {
				break;	// communication error
			} else {
				printf ("DEBUG: Copycat sent %d bytes to local %d\n", (int) sz, local);
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
	gnutls_session_t session;
	int ret;
	//
	// Check and setup file handles
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
	//
	// Negotiate TLS
	if (cmd->cmd.pio_cmd == PIOC_STARTTLS_SERVER_V1) {
		gnutls_init (&session,  GNUTLS_SERVER);
		gnutls_priority_set_direct (session, "NORMAL:+ANON-ECDH:+ANON-DH", NULL);
		gnutls_credentials_set (session, GNUTLS_CRD_ANON, srv_anoncred);
	} else {
		gnutls_init (&session, GNUTLS_CLIENT);
		gnutls_priority_set_direct (session, "PERFORMANCE:+ANON-ECDH:+ANON-DH", NULL);
		gnutls_credentials_set (session, GNUTLS_CRD_ANON, cli_anoncred);
	}
	gnutls_transport_set_int (session, passfd);
	gnutls_handshake_set_timeout (session, GNUTLS_DEFAULT_HANDSHAKE_TIMEOUT);
	do {
		ret = gnutls_handshake (session);
        } while (ret < 0 && gnutls_error_is_fatal (ret) == 0);
	if (ret < 0) {
		gnutls_deinit (session);
		fprintf (stderr, "TLS handshake failed: %s\n", gnutls_strerror (ret));
		send_error (cmd, EPERM, (char *) gnutls_strerror (ret));
		pthread_mutex_unlock (&cmd->ownership);
		close (soxx [0]);
		close (soxx [1]);
		close (passfd);
		return;
        }
	printf ("DEBUG: TLS handshake succeeded over %d\n", passfd);
	//
	// Communication outcome
	cmd->cmd.pio_data.pioc_starttls.localid [0] =
	cmd->cmd.pio_data.pioc_starttls.remoteid [0] = 0;
	send_command (cmd, soxx [0]);	// soxx [0] is app-received
	close (soxx [0]);		// assuming cross-pid dup() is finished
	pthread_mutex_unlock (&cmd->ownership);
	//
	// Copy TLS records until the connection is closed
	copycat (soxx [1], passfd, session, clientfd); // soxx [1] is pooled decryptlink
	gnutls_bye (session, GNUTLS_SHUT_WR);
	close (soxx [1]);
	close (passfd);
	gnutls_deinit (session);
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

