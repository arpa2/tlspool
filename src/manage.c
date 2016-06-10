/* tlspool/manage.c -- Management setup in local databases */


#include <syslog.h>
#include <errno.h>

#include <sys/stat.h>

#include <db.h>

#include <tlspool/internal.h>

#include "manage.h"


/*
 * The local management databases contain information that guide the
 * TLS Pool in its decisions.  The idea is that these databases are
 * filled from GUI interactions and/or central management over LDAP.
 * A concrete project to pull management information into these
 * databases can be found on http://steamworks.arpa2.net -- in terms
 * of this architecture, a TLS Pool would be a "Machine", to be driven
 * by a local "Pulley" component that pulls data into databases.
 *
 * We have selected the BerkeleyDB format.  The key-value lookup scales
 * very well, and it meets other of our requirements.  Specifically for
 * the BDB brand, there are additional facilities that make it work well,
 * such as transactional semantics and the ability to store multiple
 * values under one key.  The extra facility of replication is interesting
 * for such things as replicated services.
 *
 * Each value stored behind the key starts with 4 netbytes that can be
 * used here for management flags.  See MGT_xxx below.
 */


static DB_ENV *dbenv = NULL;

DB *dbh_localid  = NULL;
DB *dbh_disclose = NULL;
DB *dbh_trust    = NULL;


static int manage_secondary_disclose (DB *secondary, const DBT *key, const DBT *data, DBT *result) {
	// Do not add anything to the db_disclose automatically; these
	// insertions are manually made, in response to end users who
	// decide to setup access control for a site (or DoNAI).
	return 0;
}

/* Begin a database transaction, if possible; otherwise setup as NULL */
void manage_txn_begin (DB_TXN **txn) {
	int err = dbenv->txn_begin (dbenv, NULL, txn, 0);
	if (err != 0) {
		txn = NULL;
	}
}

/* Commit a database transaction, setting it to NULL.  Ignore when NULL. */
int manage_txn_commit (DB_TXN **txn) {
	int err = 0;
	if (*txn != NULL) {
		(*txn)->commit (*txn, 0);
	}
	if (err == 0) {
		*txn = NULL;
	}
	return err;
}

/* Rollback a database transaction, setting it to NULL.  Ignore when NULL. */
int manage_txn_rollback (DB_TXN **txn) {
	int err = 0;
	if (*txn != NULL) {
		err = (*txn)->abort (*txn);
	}
	if (err == 0) {
		*txn = NULL;
	}
	return err;
}

/* Setup the management databases; for the reverse, see cleanup_management() */
success_t setup_management (void) {
	u_int32_t flags = 0;
	DB_TXN *tract = NULL;
	char *dbenv_dir;
	int db_errno = 0;

	dbenv_dir = cfg_dbenv_dir ();
	if (dbenv_dir != NULL) {
		if (errno == 0) {
			mkdir (dbenv_dir, S_IRWXU);
			if (errno == 0) {
				tlog (TLOG_DB | TLOG_USER, LOG_NOTICE, "Created DB environment directory");
			} else {
				// Failure usually indicates the directory exists.
				// Whatever it was is ignored silently -- as this
				// friendly mkdir() does not constitute guaranteed
				// (or even documented) behaviour.
				errno = 0;
			}
		}
		E_d2e ("Failed to create DB environment handle",
			db_env_create (&dbenv, 0));
		E_d2e ("Failed to open dbenv_dir environment",
			dbenv->open (dbenv, dbenv_dir, DB_CREATE | DB_RECOVER | DB_INIT_TXN | DB_INIT_LOG | DB_INIT_LOCK | DB_THREAD | DB_INIT_MPOOL, S_IRUSR | S_IWUSR));
	}
	E_d2e ("Failed to create db_localid handle",
		db_create (&dbh_localid,  dbenv, 0));
	E_d2e ("Failed to create db_disclose handle",
		db_create (&dbh_disclose, dbenv, 0));
	E_d2e ("Failed to create db_trust handle",
		db_create (&dbh_trust, dbenv, 0));
	flags = DB_DUP;
	E_d2e ("Failed to set db_localid flags",
		dbh_localid->set_flags (dbh_localid,  flags));
	E_d2e ("Failed to set db_disclose flags",
		dbh_disclose->set_flags (dbh_disclose, flags));
	E_d2e ("Failed to set db_trust flags",
		dbh_trust->set_flags (dbh_trust, flags));
	flags = DB_RDONLY | DB_THREAD | DB_AUTO_COMMIT;
	E_d2e ("Failed to open db_localid",
		dbh_localid->open (dbh_localid,  tract, cfg_db_localid (),  NULL, DB_HASH, flags, 0));
	E_d2e ("Failed to open db_disclose",
		dbh_disclose->open (dbh_disclose, tract, cfg_db_disclose (), NULL, DB_HASH, flags, 0));
	E_d2e ("Failed to open db_trust",
		dbh_trust->open (dbh_trust, tract, cfg_db_trust (), NULL, DB_HASH, flags, 0));
	if (db_errno != 0) {
		cleanup_management ();
	}
	E_db_clear_errno ();
	return !errno;
}

/* Cleanup the management databases, undoing any effects of manage_setup() */
void cleanup_management (void) {
	if (dbh_disclose != NULL) {
		dbh_disclose->close (dbh_disclose, 0);
		dbh_disclose = NULL;
	}
	if (dbh_localid != NULL) {
		dbh_localid->close (dbh_localid, 0);
		dbh_localid = NULL;
	}
	if (dbh_trust != NULL) {
		dbh_trust->close (dbh_trust, 0);
		dbh_trust = NULL;
	}
	if (dbenv != NULL) {
		dbenv->close (dbenv, 0);
		dbenv = NULL;
	}
}


