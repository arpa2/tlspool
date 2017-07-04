/* pulleyback/api.c -- The API to the Pulley backend for the TLS Pool
 *
 * From: Rick van Rein <rick@openfortress.nl>
 */


#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include <errno.h>

#include "api.h"

#include "poolback.h"


/* Allocate a handler, parse information into it, access the database.
 */
void *pulleyback_open (int argc, char **argv, int varc) {
	struct pulleyback_tlspool *self;
	int rv;
	//
	// Allocate memory and wipe it clean
	self = malloc (sizeof (struct pulleyback_tlspool));
	if (self == NULL) {
		errno = ENOMEM;
		return NULL;
	}
	memset (self, 0, sizeof (struct pulleyback_tlspool));
	//
	// Parse arguments, connect to the database
	rv = parse_arguments (argc, argv, varc, self);
	if (rv != 0) {
		free (self);
		errno = EINVAL;
		return NULL;
	}
	errno = 0;
	rv = open_database (self);
	if (rv != 0) {
		free (self);
		if (errno == 0) {
			errno = ENXIO;
		}
		return NULL;
	}
	//
	// Return the successful result -- mapped to a (void *)
	return (void *) self;
}

void pulleyback_close (void *pbh) {
	struct pulleyback_tlspool *self = (struct pulleyback_tlspool *) pbh;
	if (self == NULL) {
		return;
	}
	//
	// Disconnect from the database after implicit rollback
	if (self->txn_state != TXN_NONE) {
		pulleyback_rollback (pbh);
	}
	close_database (self);
	//
	// Cleanup fields allocated with strdup()
	if (self->db_env != NULL) {
		free (self->db_env);
		self->db_env = NULL;
	}
	if (self->db_filename != NULL) {
		free (self->db_filename);
		self->db_filename = NULL;
	}
	//
	// Free the basic data structure
	free (self);
	self = NULL;
}

/* Internal method to ensure having a transaction, return 0 on error
 */
static int have_txn (struct pulleyback_tlspool *self) {
	switch (self->txn_state) {
	case TXN_NONE:
		if (0 != self->env->txn_begin (self->env, NULL, &self->txn, 0)) {
			return 0;
		}
		self->txn_state = TXN_ACTIVE;
		return 1;
	case TXN_ABORT:
	case TXN_ACTIVE:
		return 1;
	case TXN_SUCCESS:
		// You cannot have_txn() after _prepare()
		assert ((self->txn_state == TXN_NONE) || (self->txn_state == TXN_ACTIVE));
		return 0;
	}
}

/* Internal method to process a negative "ok" value by switching to TXN_ABORT
 */
static int check_txn (struct pulleyback_tlspool *self, int ok) {
	if (ok != 1) {
		if (self->txn_state == TXN_ACTIVE) {
			self->txn_state = TXN_ABORT;
		}
	}
}

int pulleyback_add (void *pbh, uint8_t **forkdata) {
	struct pulleyback_tlspool *self = (struct pulleyback_tlspool *) pbh;
	int ok = 1;
	ok = ok && have_txn (self);
	ok = ok && (self->txn_state == TXN_ACTIVE);
	ok = ok && self->update (self, forkdata, 0);
	check_txn (self, ok);
	return ok;
}

int pulleyback_del (void *pbh, uint8_t **forkdata) {
	struct pulleyback_tlspool *self = (struct pulleyback_tlspool *) pbh;
	int ok = 1;
	ok = ok && have_txn (self);
	ok = ok && (self->txn_state == TXN_ACTIVE);
	ok = ok && self->update (self, forkdata, 1);
	check_txn (self, ok);
	return ok;
}


int pulleyback_reset (void *pbh) {
	struct pulleyback_tlspool *self = (struct pulleyback_tlspool *) pbh;
	int ok = 1;
	u_int32_t count;
	ok = ok && have_txn (self);
	ok = ok && (self->txn_state == TXN_ACTIVE);
	ok = ok && (0 == self->db->truncate (self->db, self->txn, &count, 0));
	check_txn (self, ok);
	return ok;
}


/* Transactions are somewhat complex, also because they are implicitly
 * started when changes are made using _add(), _del() or _reset().
 * These operations may be conditional in the calling program, and we
 * want to aliviete the burden of maintaining a state as to whether
 * a transaction has been started implicitly, so we accept calls to
 * _prepare(), _rollback() or _commit() when no transaction exists
 * yet.  We will implement such occurrences equivalently to opening a
 * new transaction and acting on it immediately (though the logs may
 * not show it if we can optimise by not actually doing it -- it is
 * much simpler to skip the _rollback() or _commit() on an empty
 * transaction.
 *
 * We use txn_state to maintain state between _prepare() and its followup
 * call; the followup may be _prepare(), which is idempotent and will
 * return the same result; it may be _commit(), but only when the
 * preceding _prepare() has reported success; or it may be _rollback(),
 * regardless of the state reported by _prepare().
 *
 * Invalid sequences are reported through assert() -- which is not a
 * bug but a facility!  It helps the plugin user to code transaction
 * logic correctly.  The implicitness of transactions means that we
 * cannot capture all logic failures though.
 */

int pulleyback_prepare (void *pbh) {
	struct pulleyback_tlspool *self = (struct pulleyback_tlspool *) pbh;
	int ok = 1;
	switch (self->txn_state) {
	case TXN_NONE:
		// We want to return success, so we'd better create an
		// empty transaction to permit future _commit() or _rollback()
		ok = ok && have_txn (self);
		// ...continue into case TXN_ACTIVE...
	case TXN_ACTIVE:
		ok = ok && (0 == self->txn->prepare (self->txn, self->txn_gid));
		self->txn_state = ok? TXN_SUCCESS: TXN_ABORT;
		break;
	case TXN_SUCCESS:
		// The transaction has already been successfully prepared
		ok = ok && 1;
		break;
	case TXN_ABORT:
		// The transaction has already failed preparing for commit
		ok = 0;
		break;
	}
	return ok;
}

int pulleyback_commit (void *pbh) {
	struct pulleyback_tlspool *self = (struct pulleyback_tlspool *) pbh;
	int ok = 1;
	switch (self->txn_state) {
	case TXN_NONE:
		// We can safely report success when there is no transaction
		ok = 1;
		break;
	case TXN_ACTIVE:
	case TXN_SUCCESS:
		// The transaction is in full progress; attempt to commit it
		ok = ok && (0 == self->txn->commit (self->txn, 0));
		self->txn = NULL;
		self->txn_state = TXN_NONE;
		break;
	case TXN_ABORT:
		// Preparation fails, then the call should have been _rollback()
		assert (self->txn_state != TXN_ABORT);
		ok = ok && 0;
		// Since there actually is a transaction, roll it back
		ok = ok && (0 == self->txn->abort (self->txn));
		self->txn = NULL;
		self->txn_state = TXN_NONE;
		break;
	}
	return ok;
}

void pulleyback_rollback (void *pbh) {
	struct pulleyback_tlspool *self = (struct pulleyback_tlspool *) pbh;
	int ok = 1;
	switch (self->txn_state) {
	case TXN_NONE:
		// In lieu of a transaction, rollback is a trivial matter
		ok = ok && 1;
		break;
	case TXN_ABORT:
	case TXN_SUCCESS:
		// Preparation of the transaction has been done,
		// so process as we would an active transaction
	case TXN_ACTIVE:
		// When there actually is a transaction, roll it back
		ok = ok && (0 == self->txn->abort (self->txn));
		self->txn = NULL;
		self->txn_state = TXN_NONE;
		break;
	}
}

int pulleyback_collaborate (void *pbh1, void *pbh2) {
	struct pulleyback_tlspool *data1 = (struct pulleyback_tlspool *) pbh1;
	struct pulleyback_tlspool *data2 = (struct pulleyback_tlspool *) pbh2;
	int ok = 1;
	ok = ok && (0 == strcmp (data1->db_env, data2->db_env));
	//TODO// May need to copy self->env and reopen self->db in it
	if (!ok) {
		;  // Do not continue 
	} else if (data1->txn == NULL) {
		if (data2->txn == NULL) {
			// Neither has a transaction, so must create it
			ok = ok && have_txn (data2);
		}
		if (ok) {
			data1->txn = data2->txn;
		}
	} else if (data2->txn == NULL) {
		data2->txn = data1->txn;
	} else {
		ok = (data1->txn == data2->txn);
	}
	return ok;
}

