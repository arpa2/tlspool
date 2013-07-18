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
#include <gnutls/abstract.h>

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
				//TODO// GnuTLS return value processing
				break;	// communication error
			} else {
				printf ("DEBUG: Copycat sent %d bytes to remote %d\n", (int) sz, remote);
			}
		}
		if (inout [1].revents & POLLIN) {
			// Read remote and decrypt to local
			sz = gnutls_record_recv (wrapped, buf, sizeof (buf));
			//TODO// GnuTLS return value processing
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


/* The callback functions retrieve certification information for the client
 * or server in the course of the handshake procedure.
 *
 * The logic here is based on client-sent information, such as:
 *  - TLS hints -- X.509 or alternatives like OpenPGP, SRP, PSK
 *  - TLS hints -- Server Name Indication
 *  - User hints -- local and remote identities provided
 *
 * The basic procedure is to establish the simplest possible kind of
 * connection.  So, in order of preference:
 *  - PSK or SRP
 *  - OpenPGP
 *  - X.509 (the default acts as a fallback in lieu of fantasy)
 */
int retrieve_srv_certification (gnutls_session_t session,
				const gnutls_datum_t *req_ca_dn,
				int nreqs,
				const gnutls_pk_algorithm_t *pk_algos,
				int pk_algos_length,
				gnutls_pcert_st **pcert,
				unsigned int *pcert_length,
				gnutls_privkey_t *pkey) {
	gnutls_certificate_type_t certtp = gnutls_certificate_type_get (session);
	gnutls_pcert_st *pc;
	int err;
	gnutls_openpgp_crt_t pgpcrtdata;
	char *p11url = "pkcs11:manufacturer=SoftHSM&token=vanrein&id=%1A%E5%13%E8%DE%D4%86%E6%11%3B%0F%D5%E6%EE%33%BD%7F%B1%39%02"; //TODO:FIXED//
	char *localid = "rick@openfortress.nl"; //TODO:FIXED//
	switch (certtp) {
	case GNUTLS_CRT_OPENPGP:
		pc = malloc (sizeof (struct gnutls_pcert_st));	//TODO:IMPROVE
		if (!pc) {
			fprintf (stderr, "Failed to allocate PCERT structure\n");
			return GNUTLS_E_MEMORY_ERROR;
		}
		//TODO// SNI-based, existence-checking, STARTTLS_LOCALID choice
		err = ldap_fetch_openpgp_cert (&pgpcrtdata, localid);
		if (err) {
			perror ("DEBUG: OpenPGP certificate not in LDAP");
			return GNUTLS_A_CERTIFICATE_UNKNOWN;
		}
		err = -gnutls_pcert_import_openpgp (pc, pgpcrtdata, 0);
		if (err) {
			printf ("DEBUG: Failed to import OpenPGP certificate data\n");
			free (pc);
			return err;
		}
		//TODO// Fill p11url from a p11-kit search!
		//TODO// Allocate pkey as privkey_t structure
		err = -gnutls_privkey_import_pkcs11_url (*pkey, p11url);
		if (err) {
			printf ("DEBUG: Failed to import PKCS #11 private key URL for use with OpenPGP\n");
			free (pc);
			return err;
		}
		*pcert = pc;
		*pcert_length = 0;
		return GNUTLS_E_SUCCESS;
	case GNUTLS_CRT_X509:
	case GNUTLS_CRT_RAW:
	case GNUTLS_CRT_UNKNOWN:
	default:
		printf ("DEBUG: Funny sort of certificate retrieval attempted\n");
		return GNUTLS_E_CERTIFICATE_ERROR;
	}
}

/* The callback function that retrieves certification information from the
 * client in the course of the handshake procedure.
 */
int retrieve_cli_certification (gnutls_session_t session,
				const gnutls_datum_t* req_ca_dn,
				int nreqs,
				const gnutls_pk_algorithm_t* pk_algos,
				int pk_algos_length,
				gnutls_pcert_st** pcert,
				unsigned int *pcert_length,
				gnutls_privkey_t * pkey) {
	//TODO//
}

/* The callback function that retrieves a secure remote passwd for the server.
 */
int retrieve_srv_srp_creds (gnutls_session_t session,
				gnutls_datum_t *salt,
				gnutls_datum_t *verifier,
				gnutls_datum_t *g,
				gnutls_datum_t *n) {
	//TODO//
}

/* The callback function that retrieves a secure remote passwd for the client.
 * TODO: GnuTLS has not prepared for PKCS #11 based passwords yet.
 */
int retrieve_cli_srp_creds (gnutls_session_t session,
				char **username,
				char **passwd) {
	//TODO//
}

/* The callback function that retrieves a pre-shared key for the server.
 * TODO: GnuTLS has not prepared for PKCS #11 based keying yet.
 */
int retrieve_srv_psk_creds (gnutls_session_t session,
				char **username,
				gnutls_datum_t *key) {
	//TODO//
}

/* The callback function that retrieves a pre-shared key for the client.
 * TODO: GnuTLS has not prepared for PKCS #11 based keying yet.
 */
int retrieve_cli_psk_creds (gnutls_session_t session,
				char **username,
				gnutls_datum_t *key) {
	//TODO//
}

/*
 * The starttls_thread is a main program for the setup of a TLS connection,
 * either in client mode or server mode.  Note that the distinction between
 * client and server mode is only a TLS concern, but not of interest to the
 * application or the records exchanged.
 *
 * If the STARTTLS operation succeeds, this will be reported back to the
 * application, but the TLS pool will continue to be active in a copycat
 * procedure: encrypting outgoing traffic and decrypting incoming traffic.
 * TODO: Are client and server routines different?
 */
static void *starttls_thread (void *cmd_void) {
	struct command *cmd = (struct command *) cmd_void;
	int soxx [2];	// Plaintext stream between TLS pool and application
	int passfd = cmd->passfd;
	int clientfd = cmd->clientfd;
	gnutls_session_t session;
	gnutls_certificate_credentials_t *pgpcred;
	int ret;
	//
	// Permit cancellation of this thread
	errno = pthread_setcancelstate (PTHREAD_CANCEL_ENABLE, NULL);
	if (errno) {
		send_error (cmd, ESRCH, "STARTTLS handler thread cancellability refused");
		return;
	}
	//
	// Check and setup file handles
	//TODO// Distinguish between client and server through cmd
	if (passfd == -1) {
		send_error (cmd, EPROTO, "You must supply a socket");
		return;
	}
	if (socketpair (SOCK_STREAM, AF_UNIX, 0, soxx) < 0) {
		send_error (cmd, errno, "Failed to create 2ary sockets");
		return;
	}
	//
	// Negotiate TLS
	gnutls_certificate_allocate_credentials (&pgpcred);
	if (cmd->cmd.pio_cmd == PIOC_STARTTLS_SERVER_V1) {
		gnutls_init (&session,  GNUTLS_SERVER);
		gnutls_priority_set_direct (session, "NORMAL:NORMAL:+CTYPE-OPENPGP:+ANON-ECDH:+ANON-DH", NULL);
		gnutls_credentials_set (session, GNUTLS_CRD_ANON, srv_anoncred);
		gnutls_certificate_set_retrieve_function2 (&pgpcred, retrieve_srv_certification);
		//TODO// gnutls_srp_set_server_credentials_function (srv_srpcred, retrieve_srp_srv_creds);
		//TODO// gnutls_psk_set_server_credentials_function (srv_pskcred, retrieve_psk_srv_creds);
	} else {
		gnutls_init (&session, GNUTLS_CLIENT);
		gnutls_priority_set_direct (session, "PERFORMANCE:+ANON-ECDH:+ANON-DH", NULL);
		gnutls_credentials_set (session, GNUTLS_CRD_ANON, cli_anoncred);
		gnutls_certificate_set_retrieve_function2 (&pgpcred, retrieve_cli_certification);
		//TODO// gnutls_srp_set_client_credentials_function (cli_srpcred, retrieve_cli_srp_creds);
		//TODO// gnutls_psk_set_client_credentials_function (cli_pskcred, retrieve_cli_psk_creds);
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
	/* Create a thread and, if successful, wait for it to unlock cmd */
	errno = pthread_create (&cmd->handler, NULL, starttls_thread, (void *) cmd);
	if (errno) {
		send_error (cmd, ESRCH, "STARTTLS_CLIENT thread refused");
		return;
	}
	errno = pthread_detach (cmd->handler);
	if (errno) {
		pthread_cancel (cmd->handler);
		send_error (cmd, ESRCH, "STARTTLS_CLIENT thread detachment refused");
		return;
	}
}

/*
 * The starttls_server function responds to an application's request to 
 * setup TLS for a given file descriptor, and return a file descriptor
 * with the unencrypted view when done.  The main thing done here is to
 * spark off a new thread that handles the operations.
 */
void starttls_server (struct command *cmd) {
	/* Create a thread and, if successful, wait for it to unlock cmd */
	errno = pthread_create (&cmd->handler, NULL, starttls_thread, (void *) cmd);
	if (errno) {
		send_error (cmd, ESRCH, "STARTTLS_SERVER thread refused");
		return;
	}
	errno = pthread_detach (cmd->handler);
	if (errno) {
		//TODO// Kill the thread... somehow
		send_error (cmd, ESRCH, "STARTTLS_CLIENT thread detachment refused");
		return;
	}
}

