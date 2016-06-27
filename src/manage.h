/* tlspool/manage.h -- Management setup in local databases */


#include <db.h>


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

#define MGT_HDRSZ	0


/* Databases managed by the manage.c routines:
 *  - dbh_localid  is the local identity database
 *  - dbh_disclose is the disclosure database
 *  - dbh_trsut    is the trust database
 */
extern DB *dbh_localid;
extern DB *dbh_disclose;
extern DB *dbh_trust;


/* Setup the management databases.  Returns 0 on success, errno otherwise. */
success_t setup_management (void);

/* Cleanup management database state, if any.  Note that cursors are assumed
 * to have been closed by application code already.  BerkeleyDB is quite
 * strict on that, and may spill resources if cursors are left dangling when
 * closing databases, so be careful when handling errors.
 */
void cleanup_management (void);


/* Begin a database transaction, if possible; otherwise setup as NULL */
void manage_txn_begin (DB_TXN **txn);

/* Commit a database transaction, setting it to NULL.  Ignore when NULL. */
int manage_txn_commit (DB_TXN **txn);

/* Rollback a database transaction, setting it to NULL.  Ignore when NULL. */
int manage_txn_rollback (DB_TXN **txn);

