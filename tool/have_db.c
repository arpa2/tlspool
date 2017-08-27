/* tool/have_db.c -- Make sure to have all databases needed for the TLS Pool
 *
 * This utility opens the databases that are used within the TLS Pool, and
 * when they don't exist they will be silently created as empty databases.
 *
 * This facility cannot be performed by the TLS Pool, as that opens various
 * databases in readonly mode.  To support running the TLS Pool even when
 * no identities have been imported yet, run this utility before starting it.
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


const char usage[] =
"Usage: %s tlspool.conf\n"
" - tlspool.conf      is the configuration file for the TLS Pool\n"
"When this utility closes without error, then the databases for the TLS Pool\n"
"exist.  Existing databases are not overwritten, so it is safe to run this\n"
"utility, and its use is adviced in installation scripts.\n";


/* Setup and tear down management */
int setup_management (char *cfgfile, DB_ENV **dbenv, DB_TXN **txn, DB **dbh_disc, DB **dbh_lid, DB **dbh_trust) {
	char *dbenv_dir = tlspool_configvar (cfgfile, "dbenv_dir");
	char *dblid_fnm = tlspool_configvar (cfgfile, "db_localid");
	char *dbdisc_fnm = tlspool_configvar (cfgfile, "db_disclose");
	char *dbtrust_fnm = tlspool_configvar (cfgfile, "db_trust");
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
	if (dblid_fnm == NULL) {
		fprintf (stderr, "Please configure trust database name\n");
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
	if (db_create (dbh_trust, *dbenv, 0) != 0) {
		fprintf (stderr, "Failed to create trust database\n");
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
	if ((*dbh_trust)->set_flags (*dbh_trust, DB_DUP) != 0) {
		fprintf (stderr, "Failed to setup trust database for duplicate entries\n");
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
	if ((*dbh_trust)->open (*dbh_trust, *txn, dbtrust_fnm, NULL, DB_HASH, DB_CREATE | DB_THREAD, 0) != 0) {
		fprintf (stderr, "Failed to open trust database\n");
		return 0;
	}
	return 1;
}

/* Cleanup maangement structures */
void cleanup_management (DB_ENV *dbenv, DB *db_disc, DB *db_lid, DB *db_trust) {
	db_lid->close (db_lid, 0);
	db_disc->close (db_disc, 0);
	db_trust->close (db_trust, 0);
	dbenv->close (dbenv, 0);
}

int main (int argc, char *argv []) {
	uint32_t flags = 0;
	DB_ENV *dbenv;
	DB_TXN *txn;
	DB *dbh_disc;
	DB *dbh_lid;
	DB *dbh_trust;
	char *cfgfile;
	//
	// Sanity check
	if (argc < 2) {
		fprintf (stderr, usage, argv [0]);
		exit (1);
	}
	//
	// Initialise the modules taken from the src directory
	;
	//
	// Prepare variables from arguments
	cfgfile = argv [1];
	//
	// Now prepare the database for changes
	if (!setup_management (cfgfile, &dbenv, &txn, &dbh_disc, &dbh_lid, &dbh_trust)) {
		exit (1);
	}
	//
	// Commit the transaction (that involves creation of the databases)
	if (txn->commit (txn, 0) != 0) {
		fprintf (stderr, "Failed to commit transaction\n");
		exit (1);
	} else {
		fprintf (stderr, "Committed transaction\n");
	}
	//
	// Finish up and report success
success:
	cleanup_management (dbenv, dbh_disc, dbh_lid, dbh_trust);
	return 0;
	//
	// Handle failure during database interactions
failure:
	fprintf (stderr, "Rolling back transaction\n");
	txn->abort (txn);
	cleanup_management (dbenv, dbh_disc, dbh_lid, dbh_trust);
	exit (1);
}
