/* tool/tlspool_dbrecovery.c -- Run database recovery
 *
 * When BerkeleyDB returns DB_RUNRECOVERY, it requires explicit attention to
 * recovery of its database(s).  This program does just that.
 *
 * NOTE: This is a skeleton, but the recover() procedure is empty.  It has
 * been stated that BerkeleyDB does "normal recovery" on every open, which
 * works especially well on the first DB->open() call with no contenders
 * left.  For "catastrophic recovery", pre-existing backups are needed.
 * For this reason, the program is not built, even if included in the sources.
 *
 * http://docs.oracle.com/cd/E17076_04/html/gsg_txn/C/recovery.html
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
"Usage: %s tlspool.conf [--db localid] [--db disclose] [--db trust]\n"
"       Where one or more --db options indicate the databases to recover.\n"
"       Without such options, all database in tlspool.conf are recovered.\n";


/* Setup and tear down management */
int setup_management (DB_ENV **dbenv, DB_TXN **txn) {
	char *dbenv_dir = cfg_dbenv_dir ();
	char *dblid_fnm = cfg_db_localid ();
	if (dbenv_dir == NULL) {
		fprintf (stderr, "Please configure database environment directory\n");
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
}


int open_database (char *dbname, DB_ENV *dbenv, DB_TXN *txn, DB **dbh) {
	if (db_create (dbh, *dbenv, 0) != 0) {
		fprintf (stderr, "Failed to create %s database\n", dbname);
		return 0;
	}
	if ((*dbh)->set_flags (*dbh, DB_DUP) != 0) {
		fprintf (stderr, "Failed to setup %s database for duplicate entries\n", dbname);
		return 0;
	}
	if ((*dbh)->open (*dbh, *txn, dbname, NULL, DB_HASH, DB_THREAD, 0) != 0) {
		fprintf (stderr, "Failed to open %s database\n", dbname);
		return 0;
	}
	return 1;
}

/* Close the database */
void close_database (DB *db) {
	db->close (db, 0);
}

/* Cleanup maangement structures */
void cleanup_management (DB_ENV *dbenv) {
	dbenv->close (dbenv, 0);
}

/* See if the given database name is wanted for recovery */
int wanted (int argc_opt, char *argv_opt [], char *dbkwd) {
	if (argc_opt == 0) {
		return 1;
	}
	while (argc_opt-- > 0) {
		if ((argv_opt [argc_opt][0] == '-') && (argv_opt [argc_opt][1] == '-') && (strcmp (argv_opt [argc_opt] + 2, dbkwd) == )) {
			return 1;
		}
	}
	return 0;
}


/* Recover a named database */
void recover (int argc_opt, char *argv_opt [], char *dbkwd, char *dbfname) {
	if (wanted (argc_opt, argv_opt, dbkwd)) {
		dbenv->lsn_reset (dbenv, dbfname, 0);
	}
}

int main (int argc, char *argv []) {
	char *dbenvdir = NULL;
	char *dbfname = NULL;
	int argc_opt = argc - 2;
	char *argv_opt = argv + 2;
	DB_ENV *dbenv;
	DB_TXN *txn;
	DB *dbh;
	//
	// Sanity check
	if (argc_opt < 0) {
		fprintf (stderr, usage, argv [0]);
		exit (1);
	}
	if (!isatty (0)) {
		fprintf (stderr, "This is an interactive command.  Please run it in a terminal.\n");
		exit (1);
	}
	//
	// Initialise the modules taken from the src directory
	dbenvdir = tlspool_configvar (NULL, "dbenv_dir");
	if (dbenvdir == NULL) {
		fprintf (stderr, "Missing variable \"dbenv_dir\" in %s\n", argv [1]);
		exit (1);
	}
	//
	// Check if database file names are provided, and print them
	printf ("Preparing to recover the following database structures:\n");
	printf (" * Database environment, directory %s\n", dbenvdir);
	if (wanted (argc_opt, argv_opt, "localid")) {
		dbfname = cfg_db_localid ();
	} else {
		dbfname = NULL;
	}
	if (dbfname != NULL) {
		printf " * Local identity database, file %s/%s\n", dbenvdir, dbfname);
	}
	if (wanted (argc_opt, argv_opt, "disclose")) {
		dbfname = cfg_db_disclose ();
	} else {
		dbfname = NULL;
	}
	if (dbfname != NULL) {
		printf " * Disclosure database, file %s/%s\n", dbenvdir, dbfname);
	}
	if (wanted (argc_opt, argv_opt, "trust")) {
		dbfname = cfg_db_trust ();
	} else {
		dbfname = NULL;
	}
	if (dbfname != NULL) {
		printf " * Trust anchor database, file %s/%s\n", dbenvdir, dbfname);
	}
	//
	// Ask for confirmation
	printf ("\nNote well:\n");
	printf (" * Other programs should not access the database at during recovery\n");
	printf (" * This program makes no backups; you could still do this now\n");
	printf ("\nEnter \"yes\" to confirm: ");
	if (fgets (inbuf, sizeof (inbuf) - 1, stdin)) {
		if (strncmp (inbuf, "yes\n") != 0) {
			fprintf (stderr, "Aborting, as requested.  Nothing has been done to the databases.\n");
			exit (1);
		}
	}
	//
	// Start recovering
	printf ("\nConfirmation accepted.  Recovering:\n");
chdir (dbenvdir);
	if (!setup_management (&dbenv, &txn)) {
		exit (1);
	}
	recover (argc_opt, argv_opt, "localid",  cfg_db_localid  ());
	recover (argc_opt, argv_opt, "disclose", cfg_db_disclose ());
	recover (argc_opt, argv_opt, "trust",    cfg_db_trust    ());
	//
	// End recovery
	printf ("\nIf you are happy with the foregoing, we can commit the change.\n");
	printf ("\nEnter \"yes\" to confirm: ");
	if (fgets (inbuf, sizeof (inbuf) - 1, stdin)) {
		if (strncmp (inbuf, "yes\n") != 0) {
			fprintf (stderr, "Aborting, as requested.  Nothing has been done to the databases.\n");
			if (txn->abort (txn) != 0) {
				fprintf (stderr, "Transaction abort returned an error\n");
			}
			exit (1);
		}
	}
	if (txn->commit (txn, 0) != 0) {
		txn->abort (txn);
		fprintf (stderr, "Failed to commit transaction\n");
		exit (1);
	} else {
		fprintf (stderr, "Committed transaction\n");
	}
	//
	// Finish up and report success
success:
	cleanup_management (dbenv);
	return 0;
	//
	// Handle failure during database interactions
failure:
	fprintf (stderr, "Rolling back transaction\n");
	txn->abort (txn);
	cleanup_management (dbenv);
	exit (1);
}
