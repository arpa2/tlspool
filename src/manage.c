/* tlspool/manage.c -- Management setup in local databases */


#include <sys/stat.h>

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


static int manage_secondary_disclose (DB *secondary, const DBT *key, const DBT *data, DBT *result) {
	// Do not add anything to the disclose.db automatically; these
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
int setup_management (void) {
	int err = 0;
	u_int32_t flags = 0;
	DB_TXN *tract = NULL;
	mkdir ("../testdata/tlspool.env", S_IRWXU);
	err = err || db_env_create (&dbenv, 0);
if (err) printf ("MISSER %s:%d %s\n", __FILE__, __LINE__, db_strerror (err));
	err = err || dbenv->open (dbenv, "../testdata/tlspool.env", DB_CREATE | DB_RECOVER | DB_INIT_TXN | DB_INIT_LOG | DB_INIT_LOCK | DB_THREAD | DB_INIT_MPOOL, S_IRUSR | S_IWUSR);
if (err) printf ("MISSER %s:%d %s\n", __FILE__, __LINE__, db_strerror (err));
	err = err || db_create (&dbh_localid,  dbenv, 0);
if (err) printf ("MISSER %s:%d %s\n", __FILE__, __LINE__, db_strerror (err));
	err = err || db_create (&dbh_disclose, dbenv, 0);
if (err) printf ("MISSER %s:%d %s\n", __FILE__, __LINE__, db_strerror (err));
	flags = DB_DUP;
	err = err || dbh_localid->set_flags (dbh_localid,  flags);
if (err) printf ("MISSER %s:%d %s\n", __FILE__, __LINE__, db_strerror (err));
	err = err || dbh_localid->set_flags (dbh_disclose, flags);
if (err) printf ("MISSER %s:%d %s\n", __FILE__, __LINE__, db_strerror (err));
	flags = DB_RDONLY | DB_THREAD | DB_AUTO_COMMIT;
	err = err || dbh_localid->open (dbh_localid,  tract, "../localid.db",  NULL, DB_HASH, flags, 0);
if (err) printf ("MISSER %s:%d %s\n", __FILE__, __LINE__, db_strerror (err));
	err = err || dbh_localid->open (dbh_disclose, tract, "../disclose.db", NULL, DB_HASH, flags, 0);
if (err) printf ("MISSER %s:%d %s\n", __FILE__, __LINE__, db_strerror (err));
	if (err) {
		cleanup_management ();
	}
	return err;
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
	if (dbenv != NULL) {
		dbenv->close (dbenv, 0);
		dbenv = NULL;
	}
}


