/* pulleyback/api.c -- The API to the Pulley backend for the TLS Pool
 *
 * From: Rick van Rein <rick@openfortress.nl>
 */


#include <stdlib.h>
#include <string.h>

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
	// Disconnect from the database
	//TODO// Implicitly terminate a current transaction?
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
	if (self->txn == NULL) {
		if (0 != self->env->txn_begin (self->env, NULL, &self->txn, 0)) {
			return 0;
		}
		self->txn_state = TXN_ACTIVE;
	}
	return 1;
}

int pulleyback_add (void *pbh, uint8_t **forkdata) {
	struct pulleyback_tlspool *self = (struct pulleyback_tlspool *) pbh;
	int ok = 1;
	ok = ok && have_txn (self);
	ok = ok && (self->txn_state == TXN_ACTIVE);
	ok = ok && self->update (self, forkdata, 0);
	return ok;
}

int pulleyback_del (void *pbh, uint8_t **forkdata) {
	struct pulleyback_tlspool *self = (struct pulleyback_tlspool *) pbh;
	int ok = 1;
	ok = ok && have_txn (self);
	ok = ok && (self->txn_state == TXN_ACTIVE);
	ok = ok && self->update (self, forkdata, 1);
	return ok;
}


int pulleyback_reset (void *pbh) {
	struct pulleyback_tlspool *self = (struct pulleyback_tlspool *) pbh;
	int ok = 1;
	u_int32_t count;
	ok = ok && have_txn (self);
	ok = ok && (self->txn_state == TXN_ACTIVE);
	ok = ok && (0 == self->db->truncate (self->db, self->txn, &count, 0));
	return ok;
}

int pulleyback_prepare (void *pbh) {
	struct pulleyback_tlspool *self = (struct pulleyback_tlspool *) pbh;
	int ok = 1;
	ok = ok && have_txn (self);	//TODO// First look at txn_state?
	if (ok) {
		switch (self->txn_state) {
		case TXN_NONE:
		case TXN_ACTIVE:
			ok = ok && (0 == self->txn->prepare (self->txn, self->txn_gid));
			self->txn_state = ok? TXN_SUCCESS: TXN_ABORT;
			break;
		case TXN_SUCCESS:
			ok = 1;
			break;
		case TXN_ABORT:
			ok = 0;
			break;
		}
	}
	return ok;
}

int pulleyback_commit (void *pbh) {
	struct pulleyback_tlspool *self = (struct pulleyback_tlspool *) pbh;
	int ok = 1;
	ok = ok && have_txn (self);	//TODO// First look at txn_state?
	if (ok) {
		switch (self->txn_state) {
		case TXN_NONE:
		case TXN_ACTIVE:
			ok = ok && (0 == self->txn->commit (self->txn, 0));
			self->txn_state = ok? TXN_SUCCESS: TXN_ABORT;
			break;
		case TXN_ABORT:
			ok = 0;
			break;
		case TXN_SUCCESS:
			ok = 1;
			break;
		}
	}
	return ok;
}

void pulleyback_rollback (void *pbh) {
	struct pulleyback_tlspool *self = (struct pulleyback_tlspool *) pbh;
	int ok = 1;
	ok = ok && have_txn (self);	//TODO// First look at txn_state?
	if (ok) {
		switch (self->txn_state) {
		case TXN_NONE:
		case TXN_ACTIVE:
			ok = ok && (0 == self->txn->abort (self->txn));
			self->txn_state = ok? TXN_ABORT: TXN_NONE;
			break;
		case TXN_ABORT:
			ok = 1;
			break;
		case TXN_SUCCESS:
			ok = 0;
			break;
		}
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

