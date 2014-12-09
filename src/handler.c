/* tlspool/handler.c -- Setup and validation handler for TLS session */


#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <memory.h>
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


/* Generate Diffie-Hellman parameters - for use with DHE
 * kx algorithms. TODO: These should be discarded and regenerated
 * once a day, once a week or once a month. Depending on the
 * security requirements.
 */
static void generate_dh_params (void) {
	unsigned int bits;
	bits = gnutls_sec_param_to_pk_bits (
		GNUTLS_PK_DH,
		GNUTLS_SEC_PARAM_LEGACY);
	gnutls_dh_params_init (
		&dh_params);
	gnutls_dh_params_generate2 (
		dh_params,
		bits);
}

/* The global and static setup function for the handler functions.
 */
void setup_handler (void) {
	gnutls_global_init ();
	generate_dh_params ();
}


/*
 * The copycat function is a bidirectional transport between the given
 * remote and local sockets, but it will encrypt traffic from local to
 * remote, and decrypt traffic from remote to local.  It will do this
 * until one of the end points is shut down, at which time it will
 * return and assume the context will close down both pre-existing
 * sockets.
 *
 * This copycat actually has a few sharp claws to watch for -- shutdown
 * of sockets may drop the last bit of information sent.  First, the
 * signal POLLHUP is best ignored because it travels asynchronously.
 * Second, reading 0 is a good indicator of end-of-file and may be
 * followed by an shutdown of reading from that stream.  But, more
 * importantly, the other side must have this information forwarded
 * so it can shutdown.  This means that a shutdown for writing to that
 * stream is to be sent.  Even when *both* sides have agreed to not send
 * anything, they may still not have received all they were offered for
 * reading, so we should SO_LINGER on the sockets so they can acknowledge,
 * and after a timeout we can establish that shutdown failed and log and
 * return an error for it.
 * Will you believe that I had looked up if close() would suffice?  The man
 * page clearly stated yes.  However, these articles offer much more detail:
 * http://blog.netherlabs.nl/articles/2009/01/18/the-ultimate-so_linger-page-or-why-is-my-tcp-not-reliable
 * http://www.greenend.org.uk/rjk/tech/poll.html
 */
static void copycat (int local, int remote, gnutls_session_t wrapped, int master) {
	char buf [1024];
	struct pollfd inout [3];
	ssize_t sz;
	struct linger linger = { 1, 10 };
	inout [0].fd = local;
	inout [1].fd = remote;
	inout [2].fd = master;
	inout [0].events = inout [1].events = POLLIN;
	inout [2].events = 0;	// error events only
	printf ("DEBUG: Starting copycat cycle for local=%d, remote=%d\n", local, remote);
	while (((inout [0].events | inout [1].events) & POLLIN) != 0) {
		if (poll (inout, 3, -1) == -1) {
			printf ("DEBUG: Copycat polling returned an error\n");
			break;	// Polling sees an error
		}
		if (inout [0].revents & POLLIN) {
			// Read local and encrypt to remote
			sz = recv (local, buf, sizeof (buf), MSG_DONTWAIT);
			printf ("DEBUG: Copycat received %d local bytes (or error<0) from %d\n", (int) sz, local);
			if (sz == -1) {
				fprintf (stderr, "Error while receiving: %s\n", strerror (errno));
				break;	// stream error
			} else if (sz == 0) {
				inout [0].events &= ~POLLIN;
				shutdown (local, SHUT_RD);
				setsockopt (remote, SOL_SOCKET, SO_LINGER, &linger, sizeof (linger));
				gnutls_bye (wrapped, GNUTLS_SHUT_WR);
			} else if (gnutls_record_send (wrapped, buf, sz) != sz) {
				//TODO// GnuTLS return value processing
				fprintf (stderr, "gnutls_record_send() failed to pass on the requested bytes\n");
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
			if (sz < 0) {
				if (gnutls_error_is_fatal (sz)) {
					fprintf (stderr, "GnuTLS fatal error: %s\n", gnutls_strerror (sz));
					break;	// stream error
				} else {
					fprintf (stderr, "GnuTLS recoverable error: %s\n", gnutls_strerror (sz));
				}
			} else if (sz == 0) {
				inout [1].events &= ~POLLIN;
				shutdown (remote, SHUT_RD);
				setsockopt (local, SOL_SOCKET, SO_LINGER, &linger, sizeof (linger));
				shutdown (local, SHUT_WR);
			} else if (send (local, buf, sz, MSG_DONTWAIT) != sz) {
				break;	// communication error
			} else {
				printf ("DEBUG: Copycat sent %d bytes to local %d\n", (int) sz, local);
			}
		}
		inout [0].revents &= ~(POLLIN | POLLHUP); // Thy copying cat?
		inout [1].revents &= ~(POLLIN | POLLHUP); // Retract thee claws!
		if ((inout [0].revents | inout [1].revents | inout [2].revents) & ~POLLIN) {
			printf ("DEBUG: Copycat polling returned a special condition\n");
			break;	// Apparently, one of POLLERR, POLLHUP, POLLNVAL
		}
	}
	printf ("DEBUG: Ending copycat cycle for local=%d, remote=%d\n", local, remote);
}


/* The callback functions retrieve various bits of information for the client
 * or server in the course of the handshake procedure.
 *
 * The logic here is based on client-sent information, such as:
 *  - TLS hints -- X.509 or alternatives like OpenPGP, SRP, PSK
 *  - TLS hints -- Server Name Indication
 *  - User hints -- local and remote identities provided
 */
int srv_clienthello (gnutls_session_t session) {
	struct command *cmd;
	char sni [sizeof (cmd->cmd.pio_data.pioc_starttls.remoteid)]; // static
	size_t snilen = sizeof (sni);
	int snitype;
	gnutls_anon_server_credentials_t anoncred;
	gnutls_certificate_credentials_t certscred;
	int srpbits;
	gnutls_srp_server_credentials_t srpcred;
	//TODO// gnutls_kdh_server_credentials_t kdhcred;
	int err, sub;
	char *lid;

	//
	// Setup a number of common references
	cmd = (struct command *) gnutls_session_get_ptr (session);
	lid = cmd->cmd.pio_data.pioc_starttls.localid;

	//
	// Find the client-helloed ServerNameIndication, or the service name
	sni [0] = '\0';
	if (gnutls_server_name_get (session, sni, &snilen, &snitype, 0) == 0) {
		switch (snitype) {
		case GNUTLS_NAME_DNS:
			break;
		// Note: In theory, other name types could be sent, and it would
		// be useful to access indexes beyond 0.  In practice, nobody
		// uses other name types than exactly one GNUTLS_NAME_DNS.
		default:
			sni [0] = '\0';
			fprintf (stderr, "Received an unexpected SNI type; that is possible but uncommon; skipping SNI.\n");
			break;
		}
	}
	if (sni [0] != '\0') {
		if (*lid != '\0') {
			if (strncmp (sni, lid, sizeof (sni)) != 0) {
				fprintf (stderr, "Mismatch between client-sent SNI %s and local identity %s\n", sni, lid);
				return GNUTLS_E_UNEXPECTED_HANDSHAKE_PACKET;
			}
		} else {
			memcpy (lid, sni, sizeof (sni));
		}
	} else {
		memcpy (sni, lid, sizeof (sni)-1);
		sni [sizeof (sni) - 1] = '\0';
	}

	//
	// Construct server credentials for anonymous access
	gnutls_anon_allocate_server_credentials (
		&anoncred);
	gnutls_anon_set_server_dh_params (
		anoncred,
		dh_params);
	gnutls_credentials_set (
		session,
		GNUTLS_CRD_ANON,
		anoncred);

	//
	// Construct server credentials for X.509 and OpenPGP cert types
	gnutls_certificate_allocate_credentials (
		&certscred);
	gnutls_certificate_set_dh_params (
		certscred,
		dh_params);

	gnutls_certificate_set_x509_key_file (
		certscred,
		"../testdata/tlspool-test-server-cert.pem",
		"../testdata/tlspool-test-server-key.pem",
		GNUTLS_X509_FMT_PEM);
	gnutls_certificate_set_x509_trust_file (
		certscred,
		"../testdata/tlspool-test-ca-cert.pem",
		GNUTLS_X509_FMT_PEM);

	gnutls_certificate_set_openpgp_key_file (
		certscred,
		"../testdata/tlspool-test-server-pubkey.asc",
		"../testdata/tlspool-test-server-privkey.asc",
		GNUTLS_OPENPGP_FMT_BASE64);

	gnutls_credentials_set (
		session,
		GNUTLS_CRD_CERTIFICATE,
		certscred);

/*
	gnutls_certificate_server_set_request (
		session,
		GNUTLS_CERT_REQUEST);
*/

	//
	// Construct server credentials for SRP authentication
	srpbits = 3072;
	gnutls_srp_set_prime_bits (
		session,
		srpbits);
	gnutls_srp_allocate_server_credentials (
		&srpcred);
	gnutls_srp_set_server_credentials_file (
		srpcred,
		"../testdata/tlspool-test-srp.passwd",
		"../testdata/tlspool-test-srp.conf");
	gnutls_credentials_set (session,
		GNUTLS_CRD_SRP,
		srpcred);

	//
	// Construct server credentials for KDH authentication
	//TODO// gnutls_kdh_allocate_server_credentials (
	//TODO// 	&kdhcred);
	//TODO// gnutls_kdh_set_server_dh_params (
	//TODO// 	kdhcred,
	//TODO// 	dh_params);
	//TODO// gnutls_credentials_set (
	//TODO// 	session,
	//TODO// 	GNUTLS_CRD_KDH,
	//TODO// 	kdhcred);

	//
	// TODO: Setup specialised priorities string?

	//
	// Round off with an overal judgement
	return GNUTLS_E_SUCCESS;
}

/* The callback function that retrieves certification information from the
 * client in the course of the handshake procedure.
 */
int cli_cert_retrieve (gnutls_session_t session,
				const gnutls_datum_t* req_ca_dn,
				int nreqs,
				const gnutls_pk_algorithm_t* pk_algos,
				int pk_algos_length,
				gnutls_pcert_st** pcert,
				unsigned int *pcert_length,
				gnutls_privkey_t * pkey) {
	gnutls_certificate_type_t certtp = gnutls_certificate_type_get (session);
	gnutls_pcert_st *pc;
	int err;
	//TODO// char *p11url = "pkcs11:manufacturer=SoftHSM&token=vanrein&id=%1A%E5%13%E8%DE%D4%86%E6%11%3B%0F%D5%E6%EE%33%BD%7F%B1%39%02"; //TODO:FIXED//
	struct command *cmd;
	char *lid;
	gnutls_datum_t privdatum, certdatum;
	gnutls_openpgp_crt_t pgpcert;
	gnutls_openpgp_privkey_t pgppriv;
	gnutls_x509_crt_t x509cert;
	gnutls_x509_privkey_t x509priv;

	//
	// Setup a number of common references
	cmd = (struct command *) gnutls_session_get_ptr (session);
	lid = cmd->cmd.pio_data.pioc_starttls.localid;
	*pcert_length = 1;
	*pcert = (gnutls_pcert_st *) malloc (sizeof (gnutls_pcert_st));	//TODO:PREP//

	//
	// Create the structures for the response; each case returns GNUTLS_E_*
	switch (certtp) {

	case GNUTLS_CRT_OPENPGP:
		fprintf (stderr, "DEBUG: Serving OpenPGP certificate request\n");
		privdatum.data = certdatum.data = NULL;
		//TODO// SNI-based, existence-checking, STARTTLS_LOCALID choice
		//TODO// err = ldap_fetch_openpgp_cert (&certdatum, lid);
		gnutls_load_file (
			"../testdata/tlspool-test-client-pubkey.asc",
			&certdatum);
		//TODO// gnutls_privkey_import_pkcs11_url (*pkey, p11url);
		gnutls_load_file (
			"../testdata/tlspool-test-client-privkey.asc",
			&privdatum);
		// raw skips gnutls_openpgp_crt_init / gnutls_openpgp_crt_import
		gnutls_openpgp_crt_init (
			&pgpcert);
		gnutls_openpgp_crt_import (
			pgpcert,
			&certdatum,
			GNUTLS_OPENPGP_FMT_BASE64);
		gnutls_pcert_import_openpgp (
			*pcert,
			pgpcert,
			0);
		gnutls_openpgp_privkey_init (
			&pgppriv);
		gnutls_openpgp_privkey_import (
			pgppriv,
			&privdatum,
			GNUTLS_OPENPGP_FMT_BASE64,
			"",	//TODO:FIXED:NOPWD//
			0);
		//TODO// Fill p11url from a p11-kit search!
		gnutls_privkey_init (
			pkey);
		gnutls_privkey_import_openpgp (
			*pkey,
			pgppriv,
			0 /*TODO?GNUTLS_PRIVKEY_IMPORT_AUTO_RELEASE*/);
		return GNUTLS_E_SUCCESS;

	case GNUTLS_CRT_X509:
		fprintf (stderr, "DEBUG: Serving X.509 certificate request\n");
		privdatum.data = certdatum.data = NULL;
		//TODO// SNI-based, existence-checking, STARTTLS_LOCALID choice
		//TODO// err = ldap_fetch_openpgp_cert (&certdatum, lid);
		gnutls_load_file (
			"../testdata/tlspool-test-client-cert.pem",
			&certdatum);
		//TODO// gnutls_privkey_import_pkcs11_url (*pkey, p11url);
		gnutls_load_file (
			"../testdata/tlspool-test-client-key.pem",
			&privdatum);
		// raw skips gnutls_openpgp_crt_init / gnutls_openpgp_crt_import
		gnutls_x509_crt_init (
			&x509cert);
		gnutls_x509_crt_import (
			x509cert,
			&certdatum,
			GNUTLS_X509_FMT_PEM);
		gnutls_pcert_import_x509 (
			*pcert,
			x509cert,
			0);
		gnutls_x509_privkey_init (
			&x509priv);
		gnutls_x509_privkey_import2 (
			x509priv,
			&privdatum,
			GNUTLS_X509_FMT_PEM,
			"",	//TODO:FIXED:NOPWD//
			0);
		//TODO// Fill p11url from a p11-kit search!
		gnutls_privkey_init (
			pkey);
		gnutls_privkey_import_x509 (
			*pkey,
			x509priv,
			GNUTLS_PRIVKEY_IMPORT_AUTO_RELEASE);
		return GNUTLS_E_SUCCESS;

	case GNUTLS_CRT_RAW:
	case GNUTLS_CRT_UNKNOWN:
	default:
		printf ("DEBUG: Funny sort of certificate retrieval attempted\n");
		return GNUTLS_E_CERTIFICATE_ERROR;

	}
}

int cli_srpcreds_retrieve (gnutls_session_t session,
				char **username,
				char **password) {
	//TODO:FIXED//
	fprintf (stderr, "DEBUG: Picking up SRP credentials\n");
	*username = strdup ("tester");
	*password = strdup ("test");
	return GNUTLS_E_SUCCESS;
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
	struct command *cmd;
	int soxx [2];	// Plaintext stream between TLS pool and application
	int passfd;
	int clientfd;
	gnutls_session_t session;
	gnutls_certificate_credentials_t tlscred;
	int ret;

	//
	// General thread setup
	cmd = (struct command *) cmd_void;
	passfd = cmd->passfd;
	clientfd = cmd->clientfd;

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
	// Negotiate TLS; split client/server mode setup
	if (cmd->cmd.pio_cmd == PIOC_STARTTLS_SERVER_V1) {
		//
		// Setup as a TLS server
		//
		gnutls_init (&session,  GNUTLS_SERVER);
		gnutls_session_set_ptr (session, cmd);
		gnutls_priority_set_direct (
			session,
			"NORMAL:-KX-ALL:+SRP:+SRP-RSA:+SRP-DSS",
			// "NORMAL:+CTYPE-X.509:+CTYPE-OPENPGP:+CTYPE-X.509",
			// "NORMAL:+ANON-ECDH:+ANON-DH",
			NULL);
		gnutls_handshake_set_post_client_hello_function (
			session,
			srv_clienthello);

	} else if (cmd->cmd.pio_cmd == PIOC_STARTTLS_CLIENT_V1) {
		//
		// Setup as a TLS client
		//
		gnutls_anon_client_credentials_t anoncred;
		gnutls_certificate_credentials_t certcred;
		gnutls_srp_client_credentials_t srpcred;
		//TODO// gnutls_kdh_client_credentials_t kdhcred;

		//
		// Setup as a TLS client
		gnutls_init (
			&session,
			GNUTLS_CLIENT);
		gnutls_session_set_ptr (
			session,
			cmd);

		//
		// Setup for potential sending of SNI
		if (cmd->cmd.pio_data.pioc_starttls.flags & PIOF_STARTTLS_SEND_SNI) {
			char *str = cmd->cmd.pio_data.pioc_starttls.remoteid;
			int len = 0;
			while (str [len] && (len < 128)) {
				len++;
			}
			if (len == 128) {
				send_error (cmd, EINVAL, "Remote ID is not set");
				close (soxx [0]);
				close (soxx [1]);
				close (passfd);
				return;
			}
			cmd->cmd.pio_data.pioc_starttls.remoteid [127] = '\0';
			gnutls_server_name_set (
				session,
				GNUTLS_NAME_DNS,
				str,
				len);
		}

		//
		// Construct client credentials for anonymous access
		gnutls_anon_allocate_client_credentials (
			&anoncred);
		gnutls_credentials_set (
			session,
			GNUTLS_CRD_ANON,
			anoncred);

		//
		// Construct client credentials for X.509 and OpenPGP certs
		gnutls_certificate_allocate_credentials (
			&certcred);
		gnutls_certificate_set_pin_function (
			certcred,
			gnutls_pin_callback,
			NULL);
		gnutls_priority_set_direct (
			session,
			"NORMAL:+SRP:+SRP-RSA:+SRP-DSS",
			// "NORMAL:+ANON-ECDH:+ANON-DH",
			// "NORMAL:+CTYPE-X.509:+CTYPE-OPENPGP:+CTYPE-X.509",
			NULL);
		gnutls_certificate_set_x509_trust_file (
			certcred,
			"../testdata/tlspool-test-ca-cert.pem",
			GNUTLS_X509_FMT_PEM);
		gnutls_certificate_set_retrieve_function2 (
			certcred,
			cli_cert_retrieve);
		gnutls_credentials_set (
			session,
			GNUTLS_CRD_CERTIFICATE,
			certcred);

		//
		// Construct client credentials for SRP
		gnutls_srp_allocate_client_credentials (
			&srpcred);
		gnutls_srp_set_client_credentials_function (
			srpcred,
			cli_srpcreds_retrieve);
		gnutls_credentials_set (
			session,
			GNUTLS_CRD_SRP,
			srpcred);

		//
		// Construct client credentials for KDH
		//TODO// gnutls_kdh_allocate_client_credentials (
		//TODO// 	&kdhcred);
		//TODO// gnutls_kdh_set_client_credentials_function (
		//TODO// 	kdhcred,
		//TODO// 	cli_kdh_retrieve);
		//TODO// gnutls_credentials_set (
		//TODO// 	session,
		//TODO// 	GNUTLS_CRD_KDH,
		//TODO// 	kdhcred);

	} else {
		//
		// Neither a TLS client nor a TLS server
		//
		send_error (cmd, ENOTSUP, "Command not supported");
		close (soxx [0]);
		close (soxx [1]);
		close (passfd);
		return;
	}
	gnutls_transport_set_int (session, passfd);
	gnutls_handshake_set_timeout (session, GNUTLS_DEFAULT_HANDSHAKE_TIMEOUT);
	do {
		ret = gnutls_handshake (session);
        } while ((ret < 0) && (gnutls_error_is_fatal (ret) == 0));
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

