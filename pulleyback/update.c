/* pulleyback/update.c -- Collect data and update the database accordingly
 *
 * This is the actual interface to the database, harvesting information
 * from the API input, knowing that the syntax already prepared how and
 * where to find things.
 *
 * From: Rick van Rein <rick@openfortress.nl>
 */


#include <stdint.h>
#include <stdlib.h>
#include <assert.h>

#include <arpa/inet.h>

#include <quick-der/api.h>

#include "poolback.h"

/* A simple (data*,size) construct named pool_datum_t
 */
typedef struct pool_datum {
	void *data;
	size_t size;
} pool_datum_t;

typedef int db_error;

#include "../src/donai.h"
#include "../src/trust.h"


/* Internal function to check if a value is presented, either in the
 * static configuration of subtypes, or in the dynamic arguments.
 *
 * Note that this not about resources, because they reach many more
 * mutex groups, namely all those that are invalidated by it.
 */
static int check_flag (struct pulleyback_tlspool *self, enum mutexgroup mxg) {
	enum mutexgroup *args;
	if ((self->subtypes & (1 << mxg)) != 0) {
		return 1;
	}
	//TODO// Why search through args for flag bits?  Better parse them!
	for (args = self->args; *args != MXG_NONE; args++) {
		if (*args == mxg) {
			return 1;
		}
	}
	return 0;
}


/* Internal function to retrieve a data value, which is usually done from
 * the dynamically supplied arguments, with the sole exception of the
 * valexp, for which an explicit variable was created.  Return NULL when
 * the requested value was not found.
 *
 * This function is supplied with the raw data presented by Pulley.
 */
static const uint8_t *fetch_value (struct pulleyback_tlspool *self, enum mutexgroup mxg, uint8_t **data) {
	int mxi;
	if ((mxg == MXG_VALEXP) && (self->valexp != NULL)) {
		return self->valexp;
	}
	for (mxi=0; self->args [mxi] != MXG_NONE; mxi++) {
		if (self->args [mxi] == mxg) {
			return data [mxi];
		}
	}
	// We end up here if an optional argument was not provided
	return NULL;
}


/* Internal function to add or remove key/value pairs.  When rm is zero,
 * the entry will be added; otherwise, it will be removed.  Even when
 * adding, a matching record will be removed.
 *
 * The part of the database record to match is found by trimming both the
 * provided value and the database value to at most trimlen bytes and
 * comparing what remains.  Note that this comparison must also match
 * in size, so trimming to any size longer than the provided value will
 * cause a mismatch if the database value is larger.  Negative values
 * of trimlen are treated as infinite, and will thus take full records
 * into account, including their lengths.
 *
 * Another comparison trick is the inclusion of the trailing NUL char
 * at the end of a PKCS #11 URI or validation expression string.
 *
 * The array mask4 can be used to indicate flags for the first four bytes,
 * which is a big-endian flag value in localid and trust databases.
 * When NULL is provided, it will match everything.
 *
 * The function returns 1 on succes, 0 on failure.  Note that it is not
 * an error if a record to remove had already gone, or when a matching
 * record had to be removed before adding one.  This is considered to
 * be the result of manual overrides.  Failure of this function solely
 * refers to issues of a technical nature, such as I/O problems or
 * running out of memory.
 *
 * All operations on the database are excuted within the current
 * transaction; the call from api.c has ensured that one exists.
 */
static int update_db (struct pulleyback_tlspool *self,
				dercursor *key, dercursor *value,
				int trimlen, const uint8_t *mask4,
				int rm) {
	int ok = 1;
	int gotcrs = 0;
	int nomore = 1;
	DBC *crs;
	DBT db_key;
	DBT db_val;
	DBT db_got;
	uint8_t my_mask4 [] = { 0xff, 0xff, 0xff, 0xff };
	if (mask4 == NULL) {
		// When no mask4 provided, match everything
		mask4 = my_mask4;
	}
	if (trimlen < 0) {
		// Standardise on positive values that act as "infinite"
		trimlen = value->derlen + 1;
	}
	gotcrs =
	ok = ok && (0 == self->db->cursor (self->db, self->txn, &crs, 0));
	dbt_init_fixbuf (&db_key, key  ->derptr, key  ->derlen);
	dbt_init_fixbuf (&db_val, value->derptr, value->derlen);
	dbt_init_empty  (&db_got);
	nomore = crs->get (crs, &db_key, &db_got, DB_SET);
	while (!nomore) {
		int match = 1;
		int i;
		for (i = 0; match && (i < trimlen); i++) {
			match = match && (i < db_val.size);
			match = match && (i < db_got.size);
			if (match) {
				uint8_t m, a, b;
				m = (i < 4)? mask4 [i]: 0xff;
				a = m & ((uint8_t *) db_val.data) [i];
				b = m & ((uint8_t *) db_got.data) [i];
				match = (a == b);
			}
		}
		if (match) {
			crs->del (crs, 0);
		}
		nomore = crs->get (crs, &db_key, &db_got, DB_NEXT_DUP);
	}
	ok = ok && (nomore == DB_NOTFOUND);
	if (gotcrs) {
		crs->close (crs);
	}
	if (!rm) {
		ok = ok && (0 == self->db->put (
				self->db, self->txn, &db_key, &db_val, 0));
	}
	dbt_free (&db_got);
	dbt_free (&db_val);
	dbt_free (&db_key);
	return ok;
}


/* Update the disclose database, adding when rm is zero, removing otherwise.
 * Documented in detail in poolback.h
 */
int update_disclose (struct pulleyback_tlspool *self, uint8_t **data, int rm) {
	dercursor lid;
	dercursor rid;
	lid.derlen = rid.derlen = 1030;  // Sane upper margin (errors beyond)
	lid.derptr = (uint8_t *) fetch_value (self, MXG_LOCALID , data);
	rid.derptr = (uint8_t *) fetch_value (self, MXG_REMOTEID, data);
	assert (lid.derptr != NULL);
	assert (rid.derptr != NULL);
	if (der_enter (&lid) || der_enter (&rid)) {
		// Perhaps length is too small, or DER formatting error
		return 0;
	}
	return update_db (self, &rid, &lid, -1, NULL, rm);
}

/* Update the localid database, adding when rm is zero, removing otherwise.
 * Documented in detail in poolback.h
 */
int update_localid (struct pulleyback_tlspool *self, uint8_t **data, int rm) {
	dercursor lid;
	dercursor crd;
	dercursor p11;
	dercursor vex;
	uint32_t flags = 0;
	//
	// Collect DER data for localid and PKCS #11 URI
	lid.derlen =
	p11.derlen =
	vex.derlen = 1030;  // sane upper margin ~1kB
	crd.derlen = 8200;  // sane upper margin ~8kB
	lid.derptr = (uint8_t *) fetch_value (self, MXG_LOCALID, data);
	crd.derptr = (uint8_t *) fetch_value (self, MXG_CRED,    data);
	p11.derptr = (uint8_t *) fetch_value (self, MXG_PKCS11,  data);
	vex.derptr = (uint8_t *) fetch_value (self, MXG_VALEXP,  data);
	assert (lid.derptr != NULL);
	//
	// Enter the DER data to obtain contents and length
	if (crd.derptr == NULL) {
		crd.derlen = 0;
	} else {
		if (der_enter (&crd)) {
			return 0;
		}
	}
	if (der_enter (&lid)) {
		return 0;
	}
	if ((p11.derptr != NULL) && der_enter (&p11)) {
		return 0;
	}
	if ((vex.derptr != NULL) && der_enter (&vex)) {
		return 0;
	}
	//
	// Collect the flags
	if (p11.derptr == NULL) {
		flags |= LID_NO_PKCS11;
	}
	if (check_flag (self, MXG_CLIENT)) {
		flags |= LID_ROLE_CLIENT;
	}
	if (check_flag (self, MXG_SERVER)) {
		flags |= LID_ROLE_SERVER;
	}
	if (check_flag (self, MXG_X509)) {
		flags |= LID_TYPE_X509;
	} else if (check_flag (self, MXG_PGP)) {
		flags |= LID_TYPE_PGP;
	} else if (vex.derptr != NULL) {
		// Valexp is a case in localid, as an entry LID_TYPE_VALEXP
		flags |= LID_TYPE_VALEXP;
		flags &= ~LID_NO_PKCS11;
	}
	//TODO// MXG_SRP  -> LID_TYPE_SRP
	//TODO// MXG_KRB5 -> LID_TYPE_KRB5
	   else {
		return 0;
	}
	if (check_flag (self, MXG_CHAINED)) {
		flags |= LID_CHAINED;
	}
	//
	// Handle PKCS #11 URI and/or validation expression
	if (p11.derptr == NULL) {
		// Put the validation expression in the PKCS #11 URI hole
		p11 = vex;
	} else {
		assert (vex.derptr == NULL);
	}
	if (p11.derptr == NULL) {
		p11.derlen = 0;
	}
	//
	// Collect the value for this entry
	dercursor value;
	value.derlen = 4 + p11.derlen + ((p11.derptr != NULL)?1:0) + crd.derlen;
	uint8_t entry [value.derlen];
	value.derptr = entry;
	* (uint32_t *) entry = htonl (flags);
	if (p11.derptr != NULL) {
		memcpy (entry + 4, p11.derptr, p11.derlen);
		entry [4 + p11.derlen] = '\0';
	}
	if (crd.derptr != NULL) {
		memcpy (entry + 4 + p11.derlen + 1, crd.derptr, crd.derlen);
	}
	//
	// Submit the information to the database
	static const uint8_t flag4 [] = { 0x00, 0x00, 0x00, 0xff };
	return update_db (self, &lid, &value, 4, flag4, rm);
}

/* Update the trust database, adding when rm is zero, removing otherwise.
 * Documented in detail in poolback.h
 */
int update_trust (struct pulleyback_tlspool *self, uint8_t **data, int rm) {
	dercursor crd;
	dercursor vex;
	uint32_t flags = 0;
	//
	// Collect DER data for validation expression and optional credential
	vex.derlen = 1030;  // sane upper margin ~1kB
	crd.derlen = 8200;  // sane upper margin ~8kB
	crd.derptr = (uint8_t *) fetch_value (self, MXG_CRED,    data);
	vex.derptr = (uint8_t *) fetch_value (self, MXG_VALEXP,  data);
	assert (vex.derptr != NULL);
	//
	// Enter the DER data to obtain contents and length
	if (der_enter (&vex)) {
		return 0;
	}
	if (crd.derptr == NULL) {
		crd.derlen = 0;
	} else {
		if (der_enter (&crd)) {
			return 0;
		}
	}
	//
	// Collect the flags
	if (check_flag (self, MXG_CLIENT)) {
		flags |= TAD_ROLE_CLIENT;
	}
	if (check_flag (self, MXG_SERVER)) {
		flags |= TAD_ROLE_SERVER;
	}
	if (check_flag (self, MXG_X509)) {
		flags |= TAD_TYPE_X509;
	} else if (check_flag (self, MXG_PGP)) {
		flags |= TAD_TYPE_PGP;
	}
	//TODO// MXG_SRP  -> LID_TYPE_SRP
	//TODO// MXG_KRB5 -> LID_TYPE_KRB5
	   else {
		return 0;
	}
	//TODO// if (check_flag (self, MXG_NOTROOT)) {
	//TODO// 	flags |= TAD_NOTROOT;
	//TODO// }
	//
	// Collect the value for this entry
	dercursor value;
	value.derlen = 4 + vex.derlen + 1 + crd.derlen;
	uint8_t entry [value.derlen];
	value.derptr = entry;
	* (uint32_t *) entry = htonl (flags);
	memcpy (entry + 4, vex.derptr, vex.derlen);
	entry [4 + vex.derlen] = '\0';
	if (crd.derlen > 0) {
		memcpy (entry + 4 + vex.derlen + 1, crd.derptr, crd.derlen);
	}
	//
	//TODO// Determine the key for this entry
	uint8_t keybytes_TODO [] = { 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff };
	dercursor key;
	key.derptr = keybytes_TODO;
	key.derlen = sizeof (keybytes_TODO);
	//
	// Submit the information to the database
	static const uint8_t flag4 [] = { 0x00, 0x00, 0x00, 0xff };
	return update_db (self, &key, &value, 4, flag4, rm);
}

