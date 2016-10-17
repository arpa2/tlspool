/* tool/get_disclose.c -- Retrieve disclosure for local identities
 *
 * Provide a config, and a selector for remote peers which is a DoNAI or a
 * DoNAI Selector.  This commands walks all the way up the selector tree and
 * shows which of those values exist, then it lists the localid values for
 * the one that matches the selector best.  It uses the same routines as the
 * TLS Pool for doing this.
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
#include "../src/donai.h"


const char const *usage =
"Usage: %s tlspool.conf selector\n"
" - tlspool.conf      is the configuration file for the TLS Pool\n"
" - selector              is a matcher for remote peer identities\n"
"The selector may take the following forms:\n"
" - domain      matches remote peer DoNAI  completely but    with no username\n"
" - .domain     matches remote peer DoNAIs ending in .domain with no username\n"
" - .           matches any remote peer                      with no username\n"
" - user@domain matches remote peer DoNAI  with the username given\n"
" - @domain     matches remote peer DoNAIs with any username\n"
" - @.domain    matches remote peer DoNAIs with any username ending in .domain\n"
" - @.          matches remote peer DoNAIs with any username and any domain\n"
"The command walks all the way from the selector to its most abstract form, and\n"
"shows which entries exist in the disclose.db; it then picks the one that the\n"
"TLS Pool would use and prints the localid values for that one.\n";


/* Setup and tear down management */
int setup_management (char *cfgfile, DB_ENV **dbenv, DB_TXN **txn, DB **dbh_disc) {
	char *dbenv_dir = tlspool_configvar (cfgfile, "dbenv_dir");
	char *dbdisc_fnm = tlspool_configvar (cfgfile, "db_disclose");
	if (dbenv_dir == NULL) {
		fprintf (stderr, "Please configure database environment directory\n");
		return 0;
	}
	if (dbdisc_fnm == NULL) {
		fprintf (stderr, "Please configure disclose database name\n");
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
	if ((*dbh_disc)->set_flags (*dbh_disc, DB_DUP) != 0) {
		fprintf (stderr, "Failed to setup disclose database for duplicate entries\n");
		return 0;
	}
	if ((*dbh_disc)->open (*dbh_disc, *txn, dbdisc_fnm, NULL, DB_HASH, DB_THREAD | DB_RDONLY, 0) != 0) {
		fprintf (stderr, "Failed to open disclose database\n");
		return 0;
	}
	return 1;
}

/* Cleanup maangement structures */
void cleanup_management (DB_ENV *dbenv, DB *db_disc) {
	db_disc->close (db_disc, 0);
	dbenv->close (dbenv, 0);
}

int main (int argc, char *argv []) {
	char *selector = NULL;
	char *printable = NULL;
	int printable_len;
	donai_t selector_donai;
	int have_match;
	selector_t selector_1st;
	selector_t selector_iter;
	char *partstr = NULL;
	char *saveptr = NULL;
	int argi = argc;
	DB_ENV *dbenv;
	DB_TXN *txn;
	DB *dbh_disc;
	DBC *crs;
	DBT k_localid;
	DBT k_selector;
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
	printable = strdup (selector);	// Quick and easy malloc()
	if (printable == NULL) {
		fprintf (stderr, "Out of memory allocating string buffer\n");
		exit (1);
	}
	//
	// Now prepare the database
	if (!setup_management (cfgfile, &dbenv, &txn, &dbh_disc)) {
		exit (1);
	}
	if (dbh_disc->cursor (dbh_disc, txn, &crs, 0) != 0) {
		fprintf (stderr, "Failed to open database cursor on disclose.db");
		goto failure;
	}
	//
	// Chase upward from the provided selector
	printf ("Chasing up from %s the following levels are available:\n",
			selector);
	have_match = 0;
	selector_donai = donai_from_stable_string (selector, strlen (selector));
	if (selector_iterate_init (&selector_iter, &selector_donai)) do {
		int gotit = 0;
		printable_len = donai_iterate_memput (printable, &selector_iter);
		memset (&k_selector, 0, sizeof (k_selector));
		k_selector.data = printable;
		k_selector.size = printable_len;
		gotit = (crs->get (crs, &k_selector, &k_localid, DB_SET) == 0);
		printf ("Selector %.*s is %s%s\n",
			printable_len, printable,
			gotit? "present": "absent",
			(gotit && !have_match)? ", listed below": "");
		if (gotit && !have_match) {
			memcpy (&selector_1st, &selector_iter, sizeof (selector_1st));
			have_match = 1;
		}
	} while (selector_iterate_next (&selector_iter));
	//
	// Ensure that a match has been found before continuing
	if (!have_match) {
		fprintf (stderr, "No matching selector found the disclose.db\n");
		crs->close (crs);
		goto failure;
	}
	//
	// Pickup on the selector that matched first, and print its localid
	printable_len = donai_iterate_memput (printable, &selector_1st);
	printf ("\nLocal identities disclosed to remote %.*s:\n",
			printable_len, printable);
	k_selector.data = printable;
	k_selector.size = printable_len;
	nomore = crs->get (crs, &k_selector, &k_localid, DB_SET);
	while (nomore == 0) {
		printf (" - %.*s\n", k_localid.size, k_localid.data);
		nomore = crs->get (crs, &k_selector, &k_localid, DB_NEXT_DUP);
	}
	crs->close (crs);
	if (nomore != DB_NOTFOUND) {
		fprintf (stderr, "Database error encountered while iterating\n");
		goto failure;
	}
	//
	// Finally, commit the transaction
	if (txn->commit (txn, 0) != 0) {
		fprintf (stderr, "Failed to commit readonly transaction\n");
		exit (1);
	}
	//
	// Finish up and report success
success:
	cleanup_management (dbenv, dbh_disc);
	return 0;
	//
	// Handle failure during database interactions
failure:
	fprintf (stderr, "Rolling back transaction\n");
	txn->abort (txn);
	cleanup_management (dbenv, dbh_disc);
	exit (1);
}
