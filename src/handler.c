/* tlspool/handler.c -- Setup and validation handler for TLS session */


#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <memory.h>
#include <pthread.h>
#include <alloca.h>

#include <unistd.h>
#include <errno.h>
#include <poll.h>

#include <sys/types.h>
#include <sys/socket.h>

#include <gnutls/gnutls.h>
#include <gnutls/pkcs11.h>
#include <gnutls/abstract.h>

#include <tlspool/internal.h>


#include "manage.h"
#include "localid.h"


#if EXPECTED_LID_TYPE_COUNT != LID_TYPE_CNT
#error "Set EXPECTED_LID_TYPE_COUNT in <tlspool/internal.h> to match LID_TYPE_CNT"
#endif


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
 * GnuTLS infrastructure setup.
 * Session-shared DH-keys, credentials structures, and so on.
 */
static gnutls_dh_params_t dh_params;

struct credinfo {
	gnutls_credentials_type_t credtp;
	void *cred;
};

#define EXPECTED_SRV_CREDCOUNT 3
#define EXPECTED_CLI_CREDCOUNT 2
static struct credinfo srv_creds [EXPECTED_SRV_CREDCOUNT];
static struct credinfo cli_creds [EXPECTED_CLI_CREDCOUNT];
static int srv_credcount = 0;
static int cli_credcount = 0;



/* Generate Diffie-Hellman parameters - for use with DHE
 * kx algorithms. TODO: These should be discarded and regenerated
 * once a day, once a week or once a month. Depending on the
 * security requirements.
 */
static int generate_dh_params (void) {
	unsigned int bits;
	int err = GNUTLS_E_SUCCESS;
	bits = gnutls_sec_param_to_pk_bits (
		GNUTLS_PK_DH,
		GNUTLS_SEC_PARAM_LEGACY);
	//TODO// Acquire DH-params lock
	err = err || gnutls_dh_params_init (
		&dh_params);
if (err) fprintf (stderr, "MISSER: %s:%d\n", __FILE__, __LINE__);
	err = err || gnutls_dh_params_generate2 (
		dh_params,
		bits);
	//TODO// Release DH-params lock
if (err) fprintf (stderr, "MISSER: %s:%d\n", __FILE__, __LINE__);
	return err;
}

/* Load Diffie-Hellman parameters from file - or generate them when load fails.
 */
static int load_dh_params (void) {
	gnutls_dh_params_t dhp;
	gnutls_datum_t pkcs3;
	char *filename = "../testdata/tlspool-dh-params.pkcs3";
	int err = 0;
	bzero (&pkcs3, sizeof (pkcs3));
	err = err || gnutls_load_file (
		filename,
		&pkcs3);
	err = err || gnutls_dh_params_init (
		&dhp);
	err = err || gnutls_dh_params_import_pkcs3 (
		dhp,
		&pkcs3,
		GNUTLS_X509_FMT_PEM);
	if (pkcs3.data != NULL) {
		free (pkcs3.data);
	}
	if (err) {
		int sub;
		fprintf (stderr, "DEBUG: Failed to load DH params from %s; generating fresh parameters\n", filename);
		err = 0;
		err = err || generate_dh_params ();
		sub = err;
		//TODO// Acquire DH-params lock
		sub = sub || gnutls_dh_params_export2_pkcs3 (
			dh_params,
			GNUTLS_X509_FMT_PEM,
			&pkcs3);
		//TODO// Release DH-params lock
		if (!sub) {
			FILE *pemf;
			//
			// Best effor file save -- readback will parse
			pemf = fopen (filename, "w");
			if (pemf != NULL) {
				fwrite (pkcs3.data, 1, pkcs3.size, pemf);
				fclose (pemf);
				fprintf (stderr, "DEBUG: Saved DH params to %s (best-effort)\n", filename);
			}
		}
	} else {
		gnutls_dh_params_t old_dh;
		//TODO// Acquire DH-params lock
		old_dh = dh_params;
		dh_params = dhp;
		//TODO// Release DH-params lock
		if (old_dh) {
			gnutls_dh_params_deinit (old_dh);
		}
	}
	return err;
}

/* Remove DH parameters, to be used during program cleanup. */
static void remove_dh_params (void) {
	if (dh_params) {
		gnutls_dh_params_deinit (dh_params);
		dh_params = NULL;
	}
}


/* A log printing function
 */
void log_gnutls (int level, const char *msg) {
	fprintf (stderr, "GnuTLS_%d: %s", level, msg);
}


/* The global and static setup function for the handler functions.
 */
void setup_handler (void) {
	int setup_handler_credentials (void);	/* Defined below */
	const char *curver;
	int err = GNUTLS_E_SUCCESS;
	//
	// Basic library actions
	fprintf (stderr, "DEBUG: Compiled against GnuTLS version %s\n", GNUTLS_VERSION);
	curver = gnutls_check_version (GNUTLS_VERSION);
	fprintf (stderr, "DEBUG: Running against %s GnuTLS version %s\n", curver? "acceptable": "OLDER", curver? curver: gnutls_check_version (NULL));
	err = err || gnutls_global_init ();
	err = err || gnutls_pkcs11_init (GNUTLS_PKCS11_FLAG_MANUAL, NULL);
if (err) fprintf (stderr, "MISSER: %s:%d\n", __FILE__, __LINE__);
	//
	// Setup logging / debugging
	gnutls_global_set_log_function (log_gnutls);
	gnutls_global_set_log_level (2);
	//
	// Setup DH parameters
	err = err || load_dh_params ();
if (err) fprintf (stderr, "MISSER: %s:%d\n", __FILE__, __LINE__);
	fprintf (stderr, "DEBUG: Setting up management databases\n");
	//
	// Setup shared credentials for all client server processes
	err = err || setup_handler_credentials ();
	//
	// Setup the management databases
	err = err || setup_management ();
if (err) fprintf (stderr, "MISSER %s: %s:%d\n", db_strerror (err), __FILE__, __LINE__);
	if (err != GNUTLS_E_SUCCESS) {
		fprintf (stderr, "ERROR: GnuTLS setup failed: %s\n", gnutls_strerror (err));
		exit (1);
	}
}

/* Cleanup the structures and resources that were setup for handling TLS.
 */
void cleanup_handler (void) {
	void cleanup_handler_credentials (void);	/* Defined below */
	cleanup_management ();
	cleanup_handler_credentials ();
	remove_dh_params ();
	gnutls_pkcs11_deinit ();
	gnutls_global_deinit ();
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
				fprintf (stderr, "gnutls_record_send() failed to pass on the requested bytes\n");
				break;	// communication error
			} else {
				printf ("DEBUG: Copycat sent %d bytes to remote %d\n", (int) sz, remote);
			}
		}
		if (inout [1].revents & POLLIN) {
			// Read remote and decrypt to local
			sz = gnutls_record_recv (wrapped, buf, sizeof (buf));
			printf ("DEBUG: Copycat received %d remote bytes from %d (or error if <0)\n", (int) sz, remote);
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


/* The callback function that retrieves certification information from either
 * the client or the server in the course of the handshake procedure.
 */
int clisrv_cert_retrieve (gnutls_session_t session,
				const gnutls_datum_t* req_ca_dn,
				int nreqs,
				const gnutls_pk_algorithm_t* pk_algos,
				int pk_algos_length,
				gnutls_pcert_st** pcert,
				unsigned int *pcert_length,
				gnutls_privkey_t * pkey) {
	gnutls_certificate_type_t certtp;
	gnutls_pcert_st *pc = NULL;
	struct command *cmd;
	char *lid, *rid;
	gnutls_datum_t privdatum = { NULL, 0 };
	gnutls_datum_t certdatum = { NULL, 0 };
	gnutls_openpgp_crt_t pgpcert = NULL;
	gnutls_openpgp_privkey_t pgppriv = NULL;
	gnutls_x509_crt_t x509cert = NULL;
	gnutls_x509_privkey_t x509priv = NULL;
	int err = GNUTLS_E_SUCCESS;
	int lidtype;
	int lidrole = 0;
	char *rolestr;
	char sni [sizeof (cmd->cmd.pio_data.pioc_starttls.localid)];
	size_t snilen = sizeof (sni);
	int snitype;
	int ok;
	uint32_t flags;
	char *p11priv;
	uint8_t *pubdata;
	int pubdatalen;

	//
	// Setup a number of common references and structures
	*pcert = NULL;
	cmd = (struct command *) gnutls_session_get_ptr (session);
	if (cmd == NULL) {
		return -GNUTLS_E_INVALID_SESSION;
	}
	if (cmd->cmd.pio_cmd == PIOC_STARTTLS_SERVER_V1) {
		lidrole = LID_ROLE_SERVER;
		rolestr = "server";
	} else if (cmd->cmd.pio_cmd == PIOC_STARTTLS_CLIENT_V1) {
		lidrole = LID_ROLE_CLIENT;
		rolestr = "client";
	} else {
		return -GNUTLS_E_INVALID_SESSION;
	}
	lid = cmd->cmd.pio_data.pioc_starttls.localid;
	rid = cmd->cmd.pio_data.pioc_starttls.remoteid;

	//
	// On a server, lookup the server name and match it against lid.
	// TODO: For now assume a single server name in SNI (as that is normal).
	if (lidrole == LID_ROLE_SERVER) {
		if (gnutls_server_name_get (session, sni, &snilen, &snitype, 0) || (snitype != GNUTLS_NAME_DNS)) {
			return GNUTLS_E_NO_CERTIFICATE_FOUND;
		}
		if (*lid != '\0') {
			if (strncmp (sni, lid, snilen) != 0) {
				fprintf (stderr, "DEBUG: SNI %s does not match preset local identity %s\n", sni, lid);
				return GNUTLS_E_NO_CERTIFICATE_FOUND;
			}
		} else {
			// TODO: Should ask for permission before accepting SNI
			memcpy (lid, sni, sizeof (sni));
		}
	}

	//
	// Setup the lidtype parameter for responding
	certtp = gnutls_certificate_type_get (session);
	if (certtp == GNUTLS_CRT_OPENPGP) {
		fprintf (stderr, "DEBUG: Serving OpenPGP certificate request as a %s\n", rolestr);
		lidtype = LID_TYPE_PGP;
	} else if (certtp == GNUTLS_CRT_X509) {
		fprintf (stderr, "DEBUG: Serving X.509 certificate request as a %s\n", rolestr);
		lidtype = LID_TYPE_X509;
	} else {
		// GNUTLS_CRT_RAW, GNUTLS_CRT_UNKNOWN, or other
		fprintf (stderr, "DEBUG: Funny sort of certificate retrieval attempted as a %s\n", rolestr);
		return -GNUTLS_E_CERTIFICATE_ERROR;
	}

	//
	// Find the prefetched local identity to use towards this remote
	// Send a callback to the user if none is available and accessible
	if (cmd->lids [lidtype - LID_TYPE_MIN].data == NULL) {
		uint32_t oldcmd = cmd->cmd.pio_cmd;
		cmd->cmd.pio_cmd = PIOC_STARTTLS_LOCALID_V1;
		fprintf (stderr, "DEBUG: Calling send_callback_and_await_response with PIOC_STARTTLS_LOCALID_V1\n");
		cmd = send_callback_and_await_response (cmd);
		fprintf (stderr, "DEBUG: Processing callback response that sets lid:=\"%s\" for rid==\"%s\"\n", lid, rid);
		if (cmd->cmd.pio_cmd != PIOC_STARTTLS_LOCALID_V1) {
			fprintf (stderr, "DEBUG: Callback responses has bad command code\n");
			cmd->cmd.pio_cmd = oldcmd;
			return -GNUTLS_E_CERTIFICATE_ERROR;
		}
		cmd->cmd.pio_cmd = oldcmd;
		//
		// Check that new rid is a generalisation of original rid
		// Note: This is only of interest for client operation
		if (oldcmd == PIOC_STARTTLS_CLIENT_V1) {
			selector_t newrid = donai_from_stable_string (rid, strlen (rid));
			donai_t oldrid = donai_from_stable_string (cmd->orig_piocdata->remoteid, strlen (cmd->orig_piocdata->remoteid));
			if (!donai_matches_selector (&oldrid, &newrid)) {
				return GNUTLS_E_NO_CERTIFICATE_FOUND;
			}
		}
		//
		// Add (rid,lid) to disclose.db for acceptance.
		// Note that this is done within the STARTTLS transaction.
		// Upon secure setup failure this change will roll back.
		//TODO// Client => add (rid,lid) to disclose.db within cmd->txn
		//TODO// Decide how to deal with lower-level overrides
		//
		// Now reiterate to lookup lid credentials in localid.db
		err = err || fetch_local_credentials (cmd);
	}
	if (cmd->lids [lidtype - LID_TYPE_MIN].data == NULL) {
		return GNUTLS_E_NO_CERTIFICATE_FOUND;
	}

	//
	// Allocate response structures
	// TODO: Add support for certificate chains (root cert is not needed)
	// TODO: Externalise allocation / freeing
	*pcert_length = 1;
	*pcert = (gnutls_pcert_st *) malloc (sizeof (gnutls_pcert_st));		//TODO//VALGRIND//CLEANUP
	if (*pcert == NULL) {
		return -GNUTLS_E_MEMORY_ERROR;
	}

	ok = dbcred_interpret (
		&cmd->lids [lidtype - LID_TYPE_MIN],
		&flags,
		&p11priv,
		&certdatum.data,
		&certdatum.size);
	fprintf (stderr, "DEBUG: BDB entry has flags=0x%08x, p11priv=\"%s\", cert.size=%d\n", flags, p11priv, certdatum.size);
	//TODO// ok = ok && verify_cert_... (...); -- keyidlookup
	if (!ok) {
		err = GNUTLS_E_CERTIFICATE_ERROR;
	}

	//
	// Setup private key
	err = err || gnutls_privkey_init (
		pkey);		//TODO//VALGRIND//CLEANUP
if (err) fprintf (stderr, "MISSER: %s:%d\n", __FILE__, __LINE__);
	err = err || gnutls_privkey_import_pkcs11_url (
		*pkey,
		p11priv);
if (err) fprintf (stderr, "MISSER: %s:%d\n", __FILE__, __LINE__);

	//
	// Setup public key certificate
	switch (lidtype) {
	case LID_TYPE_X509:
		err = err || gnutls_pcert_import_x509_raw (
			*pcert,
			&certdatum,
			GNUTLS_X509_FMT_DER,
			0);
if (err) fprintf (stderr, "MISSER: %s:%d\n", __FILE__, __LINE__);
		break;
	case LID_TYPE_PGP:
		err = err || gnutls_pcert_import_openpgp_raw (
			*pcert,
			&certdatum,
			GNUTLS_OPENPGP_FMT_RAW,
			NULL,	/* use master key */
			0);
if (err) fprintf (stderr, "MISSER: %s:%d\n", __FILE__, __LINE__);
		break;
	default:
		/* Should not happen */
		break;
	}

	//
	// Return the overral error code, hopefully GNUTLS_E_SUCCESS
fprintf (stderr, "DEBUG: Returning %d / %s from clisrv_cert_retrieve()\n", err, gnutls_strerror (err));
	return err;
}


/* Fetch local credentials.  This can be done before TLS is started, to find
 * the possible authentication forms that can be offered.  The function
 * can additionally be used after interaction with the client to establish
 * a local identity that was not initially provided, or that was not
 * considered public at the time.
 */
int fetch_local_credentials (struct command *cmd) {
	int lidrole;
	char *lid, *rid;
	DBC *crs_disclose = NULL;
	DBC *crs_localid = NULL;
	DBT discpatn;
	DBT keydata;
	DBT creddata;
	selector_t remote_selector;
	int err = 0;
	int found = 0;

	//
	// Setup a number of common references and structures
	if (cmd->cmd.pio_cmd == PIOC_STARTTLS_SERVER_V1) {
		lidrole = LID_ROLE_SERVER;
	} else if (cmd->cmd.pio_cmd == PIOC_STARTTLS_CLIENT_V1) {
		lidrole = LID_ROLE_CLIENT;
	} else {
		return GNUTLS_E_INVALID_SESSION;
	}
	lid = cmd->cmd.pio_data.pioc_starttls.localid;
	rid = cmd->cmd.pio_data.pioc_starttls.remoteid;

	//
	// Refuse to disclose client credentials when the server name is unset;
	// note that server-claimed identities are unproven during handshake.
	if ((lidrole == LID_ROLE_CLIENT) && (*rid == '\0')) {
		fprintf (stderr, "DEBUG: No remote identity (server name) set, so no client credential disclosure\n");
		return GNUTLS_E_NO_CERTIFICATE_FOUND;
	}
	//
	// Setup database iterators to map identities to credentials
	if (lidrole == LID_ROLE_CLIENT) {
		err = err || dbh_disclose->cursor (
			dbh_disclose,
			cmd->txn,
			&crs_disclose,
			0);
if (err) fprintf (stderr, "MISSER %s: %s:%d\n", strerror (err), __FILE__, __LINE__);
	}
	err = err || dbh_localid->cursor (
		dbh_localid,
		cmd->txn,
		&crs_localid,
		0);
if (err) fprintf (stderr, "MISSER %s: %s:%d\n", strerror (err), __FILE__, __LINE__);
	//
	// Prepare for iteration over possible local identities / credentials
	char mid [128];
	char cid [128];
	if (err != 0) {
		; // Skip setup
	} else if (lidrole == LID_ROLE_CLIENT) {
		memcpy (cid, rid, sizeof (cid));
		dbt_init_fixbuf (&discpatn, cid, strlen (cid));
		dbt_init_fixbuf (&keydata,  mid, sizeof (mid)-1);
		dbt_init_malloc (&creddata);
if (err) fprintf (stderr, "MISSER %s: %s:%d\n", strerror (err), __FILE__, __LINE__);
		selector_t ridsel;
		donai_t remote_donai = donai_from_stable_string (rid, strlen (rid));
		if (!selector_iterate_init (&remote_selector, &remote_donai)) {
			err = GNUTLS_E_INVALID_REQUEST; // rid stxerr
if (err) fprintf (stderr, "MISSER %s: %s:%d\n", strerror (err), __FILE__, __LINE__);
		} else {
			err = dbcred_iterate_from_remoteid_selector (crs_disclose, crs_localid, &remote_selector, &discpatn, &keydata, &creddata);
if (err) fprintf (stderr, "MISSER %s: %s:%d\n", strerror (err), __FILE__, __LINE__);
		}
	} else {
		dbt_init_fixbuf (&discpatn, "", 0);	// Unused but good style
		dbt_init_fixbuf (&keydata,  lid, strlen (lid));
		dbt_init_malloc (&creddata);
		err = dbcred_iterate_from_localid (crs_localid, &keydata, &creddata);
if (err) fprintf (stderr, "MISSER %s: %s:%d\n", strerror (err), __FILE__, __LINE__);
	}

	//
	// Now store the local identities inasfar as they are usable
	while (err == 0) {
		int ok;
		uint32_t flags;
		int lidtype;

		fprintf (stderr, "DEBUG: Found BDB entry %s disclosed to %s\n", creddata.data + 4, (lidrole == LID_ROLE_CLIENT)? rid: "all clients");
		ok = dbcred_flags (
			&creddata,
			&flags);
		lidtype = flags & LID_TYPE_MASK;
		ok = ok && ((flags & lidrole) != 0);
		ok = ok && (lidtype >= LID_TYPE_MIN);
		ok = ok && (lidtype <= LID_TYPE_MAX);
		fprintf (stderr, "DEBUG: BDB entry has flags=0x%08x, so we (%04x/%04x) %s it\n", flags, lidrole, LID_ROLE_MASK, ok? "store": "skip ");
		if (ok) {
			// Move the credential into the command structure
			dbt_store (&creddata,
				&cmd->lids [lidtype - LID_TYPE_MIN]);
			found = 1;
		} else {
			// Skip the credential by freeing its data structure
			dbt_free (&creddata);
		}
		if (!err) {
			err = dbcred_iterate_next (crs_disclose, crs_localid, &discpatn, &keydata, &creddata);
		}
	}

	if (err == DB_NOTFOUND) {
		if (found) {
			err = 0;
		} else {
			err = GNUTLS_E_NO_CERTIFICATE_FOUND;
		}
	}
	if (crs_localid != NULL) {
		crs_localid->close (crs_localid);
		crs_localid = NULL;
	}
	if (crs_disclose != NULL) {
		crs_disclose->close (crs_disclose);
		crs_disclose = NULL;
	}
fprintf (stderr, "DEBUG: Returning %d / %s from fetch_local_credentials()\n", err, gnutls_strerror (err));
	return err;
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
	int err = GNUTLS_E_SUCCESS;
	int sub;
	int ret;
	char *lid;

	//
	// Setup a number of common references
	cmd = (struct command *) gnutls_session_get_ptr (session);
	if (cmd == NULL) {
		return -GNUTLS_E_INVALID_SESSION;
	}
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
	// TODO: Setup specialised priorities string?

	//
	// Round off with an overal judgement
	return err;
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


/* Setup credentials to be shared by all clients and servers.
 * Credentials are generally implemented through callback functions.
 * This should be called after setting up DH parameters.
 */
int setup_handler_credentials (void) {
	gnutls_anon_server_credentials_t srv_anoncred = NULL;
	gnutls_anon_client_credentials_t cli_anoncred = NULL;
	gnutls_certificate_credentials_t clisrv_certcred = NULL;
	//TODO:NOTHERE// int srpbits;
	gnutls_srp_server_credentials_t srv_srpcred = NULL;
	gnutls_srp_client_credentials_t cli_srpcred = NULL;
	//TODO// gnutls_kdh_server_credentials_t srv_kdhcred = NULL;
	//TODO// gnutls_kdh_server_credentials_t cli_kdhcred = NULL;
	int err = GNUTLS_E_SUCCESS;
	int sub;

	//
	// Construct certificate credentials for X.509 and OpenPGP cli/srv
	err = err || gnutls_certificate_allocate_credentials (
		&clisrv_certcred);
if (err) fprintf (stderr, "MISSER: %s:%d\n", __FILE__, __LINE__);
	if (!err) gnutls_certificate_set_dh_params (
		clisrv_certcred,
		dh_params);
	sub = err;
	/* TODO: Bad code.  GnuTLS 3.2.1 ignores retrieve_function2 when
	 * checking if it can handle the OpenPGP certificate type in
	 * _gnutls_session_cert_type_supported (gnutls_status.c:175) but
	 * it does see the "1" version field.  It does not callback the
	 * "1" version if "2" is present though.
	 */
	if (!sub) /* TODO:GnuTLSversions sub = */ gnutls_certificate_set_retrieve_function (
		clisrv_certcred,
		(void *) exit);
	if (!sub) /* TODO:GnuTLSversions sub = */ gnutls_certificate_set_retrieve_function2 (
		clisrv_certcred,
		clisrv_cert_retrieve);
	if (sub == GNUTLS_E_SUCCESS) {
		// Setup for certificates
		fprintf (stderr, "DEBUG: Setting client and server certificate credentials\n");
		cli_creds [cli_credcount].credtp = GNUTLS_CRD_CERTIFICATE;
		cli_creds [cli_credcount].cred   = (void *) clisrv_certcred;
		cli_credcount++;
		srv_creds [srv_credcount].credtp = GNUTLS_CRD_CERTIFICATE;
		srv_creds [srv_credcount].cred   = (void *) clisrv_certcred;
		srv_credcount++;
	} else if (clisrv_certcred != NULL) {
		gnutls_certificate_free_credentials (clisrv_certcred);
		clisrv_certcred = NULL;
	}

	//
	// Construct anonymous server credentials
	sub = err;
	sub = sub || gnutls_anon_allocate_server_credentials (
		&srv_anoncred);
if (sub) fprintf (stderr, "SUB-MISSER: %s:%d\n", __FILE__, __LINE__);
	if (!sub) gnutls_anon_set_server_dh_params (
		srv_anoncred,
		dh_params);
	if (sub == GNUTLS_E_SUCCESS) {
		fprintf (stderr, "DEBUG: Setting server anonymous credentials\n");
		srv_creds [srv_credcount].credtp = GNUTLS_CRD_ANON;
		srv_creds [srv_credcount].cred   = (void *) srv_anoncred;
		srv_credcount++;
	} else if (srv_anoncred != NULL) {
		gnutls_anon_free_server_credentials (srv_anoncred);
		srv_anoncred = NULL;
	}

#if DEFINED_MIRRORR_IMAGE_OF_SERVER_ANONYMOUS_CREDENTIALS
	//
	// Construct anonymous client credentials
	sub = err;
	sub = sub || gnutls_anon_allocate_client_credentials (
		&cli_anoncred);
if (sub) fprintf (stderr, "SUB-MISSER: %s:%d\n", __FILE__, __LINE__);
	if (!sub) gnutls_anon_set_client_dh_params (
		cli_anoncred,
		dh_params);
	if (sub == GNUTLS_E_SUCCESS) {
		fprintf (stderr, "DEBUG: Setting client anonymous credentials\n");
		cli_creds [cli_credcount].credtp = GNUTLS_CRD_ANON;
		cli_creds [cli_credcount].cred   = (void *) cli_anoncred;
		cli_credcount++;
	} else if (cli_anoncred != NULL) {
		gnutls_anon_free_client_credentials (cli_anoncred);
		cli_anoncred = NULL;
	}
#endif

	//
	// Construct server credentials for SRP authentication
	sub = err;
	sub = sub || gnutls_srp_allocate_server_credentials (
		&srv_srpcred);
if (sub) fprintf (stderr, "SUB-MISSER: %s:%d\n", __FILE__, __LINE__);
	sub = sub || gnutls_srp_set_server_credentials_file (
		srv_srpcred,
		"../testdata/tlspool-test-srp.passwd",
		"../testdata/tlspool-test-srp.conf");
if (sub) fprintf (stderr, "SUB-MISSER: %s:%d\n", __FILE__, __LINE__);
	if (sub == GNUTLS_E_SUCCESS) {
		fprintf (stderr, "DEBUG: Setting server SRP credentials\n");
		srv_creds [srv_credcount].credtp = GNUTLS_CRD_SRP;
		srv_creds [srv_credcount].cred   = (void *) srv_srpcred;
		srv_credcount++;
	} else if (srv_srpcred != NULL) {
		gnutls_srp_free_server_credentials (srv_srpcred);
		srv_srpcred = NULL;
	}

	//
	// Construct client credentials for SRP authentication
	sub = err;
	sub = sub || gnutls_srp_allocate_client_credentials (
		&cli_srpcred);
if (sub) fprintf (stderr, "SUB-MISSER: %s:%d\n", __FILE__, __LINE__);
	if (!sub) gnutls_srp_set_client_credentials_function (
		cli_srpcred,
		cli_srpcreds_retrieve);
if (sub) fprintf (stderr, "SUB-MISSER: %s:%d\n", __FILE__, __LINE__);
	if (sub == GNUTLS_E_SUCCESS) {
		fprintf (stderr, "DEBUG: Setting client SRP credentials\n");
		cli_creds [cli_credcount].credtp = GNUTLS_CRD_SRP;
		cli_creds [cli_credcount].cred   = (void *) cli_srpcred;
		cli_credcount++;
	} else if (cli_srpcred != NULL) {
		gnutls_srp_free_client_credentials (cli_srpcred);
		cli_srpcred = NULL;
	}
	err = err || sub;

	//
	// Construct server credentials for KDH authentication
	//TODO// err = err || sub;
	//TODO// sub = sub || gnutls_kdh_allocate_server_credentials (
	//TODO// 	&srv_kdhcred);
	//TODO// sub = sub || gnutls_kdh_set_server_dh_params (
	//TODO// 	srv_kdhcred,
	//TODO// 	dh_params);
	//TODO// if (sub == GNUTLS_E_SUCCESS) {
	//TODO// 	fprintf (stderr, "DEBUG: Setting server KDH credentials\n");
	//TODO// 	srv_creds [srv_credcount].credtp = GNUTLS_CRD_KDH;
	//TODO// 	srv_creds [srv_credcount].cred   = (void *) srv_kdhcred;
	//TODO// 	srv_credcount++;
	//TODO// } else if (srv_kdhcred != NULL) {
	//TODO// 	gnutls_kdh_free_server_credentials (srv_kdhcred);
	//TODO// 	srv_kdhcred = NULL;
	//TODO// }

	//
	// Construct client credentials for KDH
	//TODO// sub = err;
	//TODO// sub = sub || gnutls_kdh_allocate_client_credentials (
	//TODO// 	&cli_kdhcred);
	//TODO// sub = sub || gnutls_kdh_set_client_credentials_function (
	//TODO// 	cli_kdhcred,
	//TODO// 	cli_kdh_retrieve);
	//TODO// if (sub == GNUTLS_E_SUCCESS) {
	//TODO// 	fprintf (stderr, "DEBUG: Setting client KDH credentials\n");
	//TODO// 	cli_creds [cli_credcount].credtp = GNUTLS_CRD_KDH;
	//TODO// 	cli_creds [cli_credcount].cred   = (void *) cli_kdhcred;
	//TODO// 	cli_credcount++;
	//TODO// } else if (cli_kdhcred != NULL) {
	//TODO// 	gnutls_kdh_free_client_credentials (cli_kdhcred);
	//TODO//	cli_kdhcred = NULL;
	//TODO// }

	//
	// Ensure that at least one credential has been set
	// TODO: Look at the counters; but at boot, we can require all okay
	if ((err == GNUTLS_E_SUCCESS) &&
			( (cli_credcount != EXPECTED_CLI_CREDCOUNT) ||
			  (srv_credcount != EXPECTED_SRV_CREDCOUNT) ) ) {
		fprintf (stderr, "DEBUG: Not all credential types could be setup (cli %d/%d, srv %d/%d, err %d)\n", cli_credcount, EXPECTED_CLI_CREDCOUNT, srv_credcount, EXPECTED_SRV_CREDCOUNT, err);
		err = GNUTLS_E_INSUFFICIENT_CREDENTIALS;
if (err) fprintf (stderr, "MISSER: %s:%d\n", __FILE__, __LINE__);
	}

	//
	// Report overall error or success
	return err;
}


/* Cleanup all credentials created, just before exiting the daemon.
 */
void cleanup_handler_credentials (void) {
	while (srv_credcount-- > 0) {
		struct credinfo *crd = &srv_creds [srv_credcount];
		switch (crd->credtp) {
		case GNUTLS_CRD_CERTIFICATE:
			// Shared with client; skipped in server and removed in client
			// gnutls_certificate_free_credentials (crd->cred);
			break;
		case GNUTLS_CRD_ANON:
			gnutls_anon_free_server_credentials (crd->cred);
			break;
		case GNUTLS_CRD_SRP:
			gnutls_srp_free_server_credentials (crd->cred);
			break;
		//TODO// case GNUTLS_CRD_KDH:
		//TODO// 	gnutls_kdh_free_server_credentials (crd->cred);
		//TODO// 	break;
		}
	}
	while (cli_credcount-- > 0) {
		struct credinfo *crd = &cli_creds [cli_credcount];
		switch (crd->credtp) {
		case GNUTLS_CRD_CERTIFICATE:
			// Shared with client; skipped in server and removed in client
			gnutls_certificate_free_credentials (crd->cred);
			break;
		case GNUTLS_CRD_ANON:
			gnutls_anon_free_client_credentials (crd->cred);
			break;
		case GNUTLS_CRD_SRP:
			gnutls_srp_free_client_credentials (crd->cred);
			break;
		//TODO// case GNUTLS_CRD_KDH:
		//TODO// 	gnutls_kdh_free_client_credentials (crd->cred);
		//TODO// 	break;
		}
	}
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
	struct pioc_starttls orig_piocdata;
	uint32_t orig_cmd;
	int soxx [2];	// Plaintext stream between TLS pool and application
	int passfd;
	int clientfd;
	gnutls_session_t session;
	int err = GNUTLS_E_SUCCESS;
	int sub;
	int ret;
	int i;
	struct credinfo *clisrv_creds;
	int clisrv_credcount;

	//
	// General thread setup
	cmd = (struct command *) cmd_void;
	if (cmd == NULL) {
		send_error (cmd, EINVAL, "Command structure not received");
		return;
	}
	orig_cmd = cmd->cmd.pio_cmd;
	memcpy (&orig_piocdata, &cmd->cmd.pio_data.pioc_starttls, sizeof (orig_piocdata));
	cmd->orig_piocdata = &orig_piocdata;
	passfd = cmd->passfd;
	clientfd = cmd->clientfd;

	//
	// Setup BDB transactions and reset credential datum fields
	bzero (&cmd->lids, sizeof (cmd->lids));	//TODO: Probably double work?
	manage_txn_begin (&cmd->txn);

	//
	// Permit cancellation of this thread -- TODO: Cleanup?
	errno = pthread_setcancelstate (PTHREAD_CANCEL_ENABLE, NULL);
	if (errno) {
		send_error (cmd, ESRCH, "STARTTLS handler thread cancellability refused");
		return;
	}
	//
	// Check and setup file handles
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
	if (orig_cmd == PIOC_STARTTLS_SERVER_V1) {
		//
		// Setup as a TLS server
		//
		err = err || gnutls_init (&session,  GNUTLS_SERVER);
if (err) fprintf (stderr, "MISSER: %s:%d\n", __FILE__, __LINE__);
		if (!err) gnutls_session_set_ptr (session, cmd);
		if (!err) gnutls_handshake_set_post_client_hello_function (
			session,
			srv_clienthello);
		//
		// Setup for server credential installation in this session
		clisrv_creds     = srv_creds;
		clisrv_credcount = srv_credcount;

	} else if (orig_cmd == PIOC_STARTTLS_CLIENT_V1) {
		//
		// Setup as a TLS client
		//
		int srpbits;
		//
		// Require a minimum security level for SRP
		srpbits = 3072;
		//TODO:CRASH// if (!sub) gnutls_srp_set_prime_bits (
			//TODO:CRASH// session,
			//TODO:CRASH// srpbits);
		//
		// Setup as a TLS client
		err = err || gnutls_init (
			&session,
			GNUTLS_CLIENT);
if (err) fprintf (stderr, "MISSER: %s:%d\n", __FILE__, __LINE__);
		if (!err) gnutls_session_set_ptr (
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
			cmd->cmd.pio_data.pioc_starttls.remoteid [sizeof (cmd->cmd.pio_data.pioc_starttls.remoteid)-1] = '\0';
			err = err || gnutls_server_name_set (
				session,
				GNUTLS_NAME_DNS,
				str,
				len);
if (err) fprintf (stderr, "MISSER: %s:%d\n", __FILE__, __LINE__);
		}
		//
		// Setup for client credential installation in this session
		clisrv_creds     = cli_creds;
		clisrv_credcount = cli_credcount;

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

	//
	// Install the shared credentials for the client or server role
	for (i=0; i<clisrv_credcount; i++) {
		err = err || gnutls_credentials_set (
			session,
			clisrv_creds [i].credtp,
			clisrv_creds [i].cred  );
	}

	//
	// Prefetch local identities that might be used in this session
	err = err || fetch_local_credentials (cmd);

	//
	// Setup the priority string for this session
	// TODO: Derive the sting from available local identities
	// Variation factors:
	//  - starting configuration (can it be empty?)
	//  - Configured security parameters (database? variable?)
	//  - CTYPEs, SRP, ANON-or-not --> fill in as + or - characters
	if (!err) {
		err = gnutls_priority_set_direct (
		session,
		// "NORMAL:-KX-ALL:+SRP:+SRP-RSA:+SRP-DSS",
		// "NORMAL:+CTYPE-X.509:-CTYPE-OPENPGP:+CTYPE-X.509",
		"NORMAL:-CTYPE-X.509:+CTYPE-OPENPGP:-CTYPE-X.509",
		// "NORMAL:+ANON-ECDH:+ANON-DH",
		NULL);
if (err) fprintf (stderr, "MISSER %s: %s:%d\n", gnutls_strerror (err), __FILE__, __LINE__);
	}

	//
	// Now setup for the GnuTLS handshake
	//
	if (!err) gnutls_transport_set_int (session, passfd);
	if (!err) gnutls_handshake_set_timeout (session, GNUTLS_DEFAULT_HANDSHAKE_TIMEOUT);
	if (err) {
		fprintf (stderr, "Failed to prepare for TLS: %s\n", gnutls_strerror (err));
		send_error (cmd, EIO, "Failed to prepare for TLS");
		close (soxx [0]);
		close (soxx [1]);
		close (passfd);
		return;
	}
	do {
		err = gnutls_handshake (session);
if (err) fprintf (stderr, "MISSER: %s:%d\n", __FILE__, __LINE__);
        } while ((err < 0) && (gnutls_error_is_fatal (err) == 0));

	//
	// Cleanup any prefetched identities
	for (i=LID_TYPE_MIN; i<=LID_TYPE_MAX; i++) {
		if (cmd->lids [i - LID_TYPE_MIN].data != NULL) {
			free (cmd->lids [i - LID_TYPE_MIN].data);
		}
	}
	bzero (cmd->lids, sizeof (cmd->lids));

	//
	// From here, assume nothing about the cmd structure; as part of the
	// handshake, it may have passed through the client's control, as
	// part of a callback.  So, reinitialise the entire return structure.
	//TODO// Or backup the (struct pioc_starttls) before handshaking
	cmd->cmd.pio_cmd = orig_cmd;
	cmd->cmd.pio_data.pioc_starttls.localid  [0] =
	cmd->cmd.pio_data.pioc_starttls.remoteid [0] = 0;

	//
	// Respond to positive or negative outcome of the handshake
	if (err < 0) {
		gnutls_deinit (session);
		fprintf (stderr, "TLS handshake failed: %s\n", gnutls_strerror (err));
		send_error (cmd, EPERM, "TLS handshake failed");
		manage_txn_rollback (&cmd->txn);
		close (soxx [0]);
		close (soxx [1]);
		close (passfd);
		return;
        } else {
		printf ("DEBUG: TLS handshake succeeded over %d\n", passfd);
		manage_txn_commit (&cmd->txn);
		//TODO// extract_authenticated_remote_identity (cmd);
	}

	//
	// Communicate outcome
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

