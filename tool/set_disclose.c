/* tool/set_disclose.c -- Setup disclosure for local identities
 *
 * Provide a config, a selector for remote peers and a list of local DoNAIs.
 * The command erases all matching old entries, and installs any new ones.
 *
 * From: Rick van Rein <rick@openfortress.nl>
 */


#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

#include <db.h>

#include <tlspool/internal.h>


const char const *usage =
"Usage: %s tlspool.conf selector [[user@]domain...]\n"
" - tlspool.conf      is the configuration file for the TLS Pool\n"
" - selector              is a matcher for remote peer identities\n"
" - user@domain or domain is a local client network access identifier\n"
"The list of client identities replaces the old list.  An empty list is nothing\n"
"special; it replaces the old content with zero entries.\n"
"The selector may take the following forms:\n"
" - domain      matches remote peer DoNAI  completely but    with no username\n"
" - .domain     matches remote peer DoNAIs ending in .domain with no username\n"
" - .           matches any remote peer                      with no username\n"
" - user@domain matches remote peer DoNAI  with the username given\n"
" - @domain     matches remote peer DoNAIs with any username\n"
" - @.domain    matches remote peer DoNAIs with any username ending in .domain\n"
" - @.          matches remote peer DoNAIs with any username and any domain\n"
"When multiple selectors match a remote DoNAI, only the most concrete applies.\n"
"When no selector matches a remote DoNAI, the default policy is to reject.\n"
"An empty [[user@]domain] list is nothing special; it removes old content.\n";


/* Setup and tear down management */
int setup_management (char *cfgfile, DB_ENV **dbenv, DB_TXN **txn, DB **dbh_disc, DB **dbh_lid) {
	char *dbenv_dir = tlspool_configvar (cfgfile, "dbenv_dir");
	char *dblid_fnm = tlspool_configvar (cfgfile, "db_localid");
	char *dbdisc_fnm = tlspool_configvar (cfgfile, "db_disclose");
	if (dbenv_dir == NULL) {
		fprintf (stderr, "Please configure database environment directory\n");
		return 0;
	}
	if (dbdisc_fnm == NULL) {
		fprintf (stderr, "Please configure disclose database name\n");
		return 0;
	}
	if (dblid_fnm == NULL) {
		fprintf (stderr, "Please configure localid database name\n");
		return 0;
	}
	if (db_env_create (dbenv, 0) != 0) {
		fprintf (stderr, "Failed to create database environment");
		return 0;
	}
	if ((*dbenv)->open (*dbenv, dbenv_dir, DB_CREATE | DB_RECOVER | DB_INIT_TXN | DB_INIT_LOG | DB_INIT_LOCK | DB_THREAD | DB_INIT_MPOOL, S_IRUSR | S_IWUSR) != 0) {
		fprintf (stderr, "Failed to open database environment");
		return 0;
	}
	if ((*dbenv)->txn_begin (*dbenv, NULL, txn, 0) != 0) {
		fprintf (stderr, "Failed to start transaction\n");
		exit (1);
	}
	if (db_create (dbh_disc, *dbenv, 0) != 0) {
		fprintf (stderr, "Failed to create disclose database\n");
		return 0;
	}
	if (db_create (dbh_lid, *dbenv, 0) != 0) {
		fprintf (stderr, "Failed to create localid database\n");
		return 0;
	}
	if ((*dbh_disc)->set_flags (*dbh_disc, DB_DUP) != 0) {
		fprintf (stderr, "Failed to setup disclose database for duplicate entries\n");
		return 0;
	}
	if ((*dbh_lid)->set_flags (*dbh_lid, DB_DUP) != 0) {
		fprintf (stderr, "Failed to setup localid database for duplicate entries\n");
		return 0;
	}
	if ((*dbh_disc)->open (*dbh_disc, *txn, dbdisc_fnm, NULL, DB_HASH, DB_CREATE | DB_THREAD, 0) != 0) {
		fprintf (stderr, "Failed to open disclose database\n");
		return 0;
	}
	if ((*dbh_lid)->open (*dbh_lid, *txn, dblid_fnm, NULL, DB_HASH, DB_CREATE | DB_THREAD, 0) != 0) {
		fprintf (stderr, "Failed to open disclose database\n");
		return 0;
	}
	return 1;
}

/* Cleanup maangement structures */
void cleanup_management (DB_ENV *dbenv, DB *db_disc, DB *db_lid) {
	db_lid->close (db_lid, 0);
	db_disc->close (db_disc, 0);
	dbenv->close (dbenv, 0);
}

int main (int argc, char *argv []) {
	char *selector = NULL;
	char *partstr = NULL;
	char *saveptr = NULL;
	char *p11uri = NULL;
	uint8_t e_buf [5000];
	int argi = argc;
	int filesz = 0;
	int p11len = 0;
	struct stat statbuf;
	uint32_t flags = 0;
	DB_ENV *dbenv;
	DB_TXN *txn;
	DB *dbh_disc;
	DB *dbh_lid;
	DBC *crs;
	DBT k_localid;
	DBT k_selector;
	DBT e_value;
	int nomore;
	int fd;
	char *cfgfile;
	//
	// Sanity check
	if (argc < 3) {
		fprintf (stderr, usage, argv [0]);
		exit (1);
	}
	//
	// Initialise the modules taken from the src directory
	;
	//
	// Prepare variables from arguments
	cfgfile = argv [1];
	selector = argv [2];
	//
	// Now prepare the database for changes
	if (!setup_management (cfgfile, &dbenv, &txn, &dbh_disc, &dbh_lid)) {
		exit (1);
	}
	//
	// Verify that the to-be-introduced localid values occur in localid.db
	argi = 3;
	if (dbh_lid->cursor (dbh_lid, txn, &crs, 0) != 0) {
		fprintf (stderr, "Failed to open cursor on localid.db\n");
		goto failure;
	}
	while (argi < argc) {
		memset (&k_localid, 0, sizeof (k_localid));
		k_localid.data = argv [argi];
		k_localid.size = strlen (argv [argi]);
		if (crs->get (crs, &k_localid, &e_value, DB_SET) != 0) {
			fprintf (stderr, "Unknown local identity: %s\n", argv [argi]);
			crs->close (crs);
			goto failure;
		}
		argi++;
	}
	crs->close (crs);
	//
	// We now know that all localid values are present in this transaction
	// We can safely continue into removal of the old values and add new ones
	if (dbh_disc->cursor (dbh_disc, txn, &crs, 0) != 0) {
		fprintf (stderr, "Failed to open cursor on disclose.db\n");
		goto failure;
	}
	memset (&k_selector, 0, sizeof (k_selector));
	k_selector.data = selector;
	k_selector.size = strlen (selector);
	nomore = crs->get (crs, &k_selector, &e_value, DB_SET);
	while (nomore == 0) {
		printf ("Removing local identity %.*s\n",
				e_value.size, e_value.data);
		if (crs->del (crs, 0) != 0) {
			fprintf (stderr, "Failed to delete record\n");
			crs->close (crs);
			goto failure;
		}
		nomore = crs->get (crs, &k_selector, &e_value, DB_NEXT_DUP);
	}
	crs->close (crs);
	if (nomore != DB_NOTFOUND) {
		fprintf (stderr, "Database error encountered while iterating\n");
		goto failure;
	}
	//
	// Now append the new loclid values
	argi = 3;
	while (argi < argc) {
		k_localid.data = argv [argi];
		k_localid.size = strlen (argv [argi]);
		printf ("Adding local identity %.*s\n",
				k_localid.size, k_localid.data);
		if (dbh_disc->put (dbh_disc, txn, &k_selector, &k_localid, 0) != 0) {
			fprintf (stderr, "Failed to write record\n");
			crs->close (crs);
			goto failure;
		}
		argi++;
	}
	//
	// Finally, commit the transaction
	if (txn->commit (txn, 0) != 0) {
		fprintf (stderr, "Failed to commit transaction\n");
		exit (1);
	} else {
		fprintf (stderr, "Committed transaction\n");
	}
	//
	// Finish up and report success
success:
	cleanup_management (dbenv, dbh_disc, dbh_lid);
	return 0;
	//
	// Handle failure during database interactions
failure:
	fprintf (stderr, "Rolling back transaction\n");
	txn->abort (txn);
	cleanup_management (dbenv, dbh_disc, dbh_lid);
	exit (1);
}
