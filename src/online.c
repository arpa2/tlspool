/* tlspool/online.c -- TLS pool online/live validation logic */


/* Most of the work done in this module returns one of three values:
 *
 * ONLINE_SUCCESS  -- online information was found to confirm the request
 * ONLINE_NOTFOUND -- online information was not found
 * ONLINE_INVALID  -- online information was found; it invalidates the request
 *
 * The idea is that optional verification must not be ONLINE_INVALID, while
 * verifications that must be enforced are checked to return ONLINE_SUCCESS.
 * Two routines with the same prototype exist to facilitate these styles
 * of judgement, namely online2success_enforced() and
 * online2success_optional().  These return 1 on success and 0 on failure.
 * Each fits in a variable of the online2success_t type.
 */


#include <stdint.h>

#include <assert.h>

#include <ldap.h>

#include <tlspool/commands.h>
#include <tlspool/internal.h>


/* Data structures for internal state/cursor storage.
 */

typedef union online_crs {
	int TODO_placeholder;
	/* cursor A */
	/* cursor B */
} crs_st, *crs_t;

typedef union online_val {
	int TODO_placeholder;
	/* current value A */
	/* current value B */
} val_st, *val_t;

typedef struct crsval {
	crs_st crs;
	val_st val;
} crsval_st, *crsval_t;


/* Searching in the global directory can follow a number of profiles.
 *
 * 1. The choice what SRV record under the domain name to look for;
 * by default, this is "_ldap._tcp" but it may be overridden with a
 * servicestring "pgpkey-ldap" to form "_pgpkey-ldap._tcp" for SRV.
 *
 * 2. There may be a need to lookup a root to start from, such as for
 * PGP, which assumes an attribute "pgpBaseKeySpaceDN" and a root class
 * "pgpServerInfo".  Similar things apply to Kerberos, though that is
 * not currently published.  WE ARE ASSUMING THAT A UID LOOKUP UNDER
 * THE ROOT WILL SUFFICE IN ANY CASE.
 *
 * 3. The search will address "dc=example,dc=com" for example.com.
 * If a username is supplied, it will be searched for in a configurable
 * manner.  Normally, a search for "(uid=john)" is done for john@example.com;
 * however, a form like "(mail=john@example.com)" is also possible, and
 * so is "(pgpUserId=*<john@example.com>*)".
 *
 * 4. The result from the output will be seen as an attribute (by OID or
 * name) whose value should match a given thing.
 *
 * To capture all these options, we need a number of steps that we captured
 * into a number of profiles below.  They can be quoted by dependent software,
 * and used abstractly, so without knowing details about the LDAP service.
 *
 * Each of these steps is fairly general in nature, and can be captured in
 * a structure that services not only the global directory but also the other
 * online structures:
 *  - iterable by functions that return ONLINE_xxx values
 *  - receiving a reference, initially NULL, to "where we are" as a (val_t)
 *  - receiving a remote identity as a (char *)
 *  - having an integer value "crslen" to allocate as a cursor
 *  - having an optional "eval" routine to return a final ONLINE_xxx value
 *  - having a "first" routine that returns 0 on failure
 *  - having a "next" routine if multiplicity is possible, returns 0 at end
 *  - having a "clean" routine, if needed, to cleanup after "first", "next"
 *  - having parameters to pass to the "first" and "next" routines
 *  - maintaining a cursor as a (crs_t) with child-value (val_t)
 *  - having potential follow-up steps for each "first" and "next" finding
 *  - having potential alt strategies if a branch returns ONLINE_NOTFOUND
 */

struct online_profile {
	struct online_profile *altstrat;
	struct online_profile *child;
	int  (*eval ) (          char *, uint8_t *, uint16_t, val_t, void *);
	int  (*first) (crsval_t, char *, uint8_t *, uint16_t, val_t, void *);
	int  (*next ) (crsval_t, char *, uint8_t *, uint16_t, val_t);
	void (*clean) (crsval_t,                              val_t);
	uint16_t crslen;	/* TODO - crslen replaceable by depth/crs_t */
	void *param;
	uint16_t depth;		/* Never define, autocomputed when set to 0 */
};


int online2success_enforced (int online) {
	return online == ONLINE_SUCCESS;
}

int online2success_optional (int online) {
	return online != ONLINE_INVALID;
}


/* Return the "depth", which is the maximum number of parent+child levels
 * under any alternative strategy variation.  When a "depth" value is
 * 0 (for undefined), compute it first.
 *
 * This is useful because it makes asynchronous storage size predictable,
 * assuming that alternatives are tried one at a time, depth-first.
 */
static uint16_t online_profile_depth (online_profile_t *prf) {
	if (prf->depth != 0) {
		return prf->depth;
	}
	if (prf->child == NULL) {
		prf->depth = 1;
	} else {
		prf->depth = 1 + online_profile_depth (prf->child);
	}
	if (prf->altstrat != NULL) {
		uint16_t altdep = online_profile_depth (prf->altstrat);
		if (altdep > prf->depth) {
			prf->depth = altdep;
		}
	}
	assert (prf->depth != 0);
	return prf->depth;
}


/* Pass through an online profile, searching for a certain result but
 * returning ONLINE_NOTFOUND if nothing works.  The intermediate result
 * ONLINE_INVALID may be overruled by an alternative strategy if it
 * yields ONLINE_SUCCESS, but not if it returns ONLINE_NOTFOUND.
 *
 * FWIW, an alternate strategy generally follows another structure,
 * rather than merely iterating over similarly-styled multi-responses.
 *
 * In some future release, this routine should be made asynchronous.
 * It would then consider one alternative strategy at a time, and move
 * to another one in a depth-first manner upon failure to deliver by
 * a considered alternative.
 */
int online_run_profile (online_profile_t *prf,
				char *rid, uint8_t *data, uint16_t len,
				val_t hdl) {
	int retval = ONLINE_NOTFOUND;
	int retval_invalid = 0;
	assert (prf != NULL);
	if (prf->eval != NULL) {
		retval = prf->eval (rid, data, len, hdl, prf->param);
	}
	while (retval == ONLINE_NOTFOUND) {
		crsval_st cursor;
		assert (prf->first != NULL);
		int todo = (prf->first != NULL) && prf->first (&cursor, rid, data, len, hdl, prf->param);
		while (todo) {
			retval = online_run_profile (prf->child, rid, data, len, &cursor.val);
			todo = (retval == ONLINE_NOTFOUND) &&
				(prf->next != NULL) &&
				prf->next (&cursor, rid, data, len, hdl);
		}
		if (prf->clean != NULL) {
			prf->clean (&cursor, hdl);
		}
		if (retval == ONLINE_INVALID) {
			prf = prf->altstrat;
			if (prf != NULL) {
				retval_invalid = 1;
				retval = ONLINE_NOTFOUND;
			}
		}
	}
	if ((retval == ONLINE_SUCCESS) && (retval_invalid > 0)) {
		retval = ONLINE_INVALID;
	}
	return retval;
}


/********** PROFILE-SPECIFIC ROUTINES **********/

//TODO: Look into DNS (for SRV)
//TODO: Look into DNS (for A/AAAA/CNAME)
//TODO: Look into DANE (for TLSA, based on SRVhostname/port)
//TODO: Look into DANE (for TLSA, based on domainname/port)
//TODO: Look into LDAP (connect to server)
//TODO: Look into LDAP (for redirection of root)
//TODO: Look into LDAP (search for object)
//TODO: Look into LDAP (compare attribute)


/********** PROFILE DEFINITION STRUCTURES **********/

//TODO: online_profile_t online_globaldir_x509_profile = { ... };
//TODO: online_profile_t online_dane_x509_profile = { ... };


/********** MODULE MANAGEMENT ROUTINES **********/

void setup_online (void) {
	/* Nothing to do */ ;
}

void cleanup_online (void) {
	/* Nothing to do */ ;
}

