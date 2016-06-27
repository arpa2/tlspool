/* trust.c -- Validate a trust anchor according to the trust anchor database.
 *
 * This interprets and handles the trust database through somewhat convenient
 * functions.  They are meant for general handling, not especially for TLS,
 * for instance.
 *
 * From: Rick van Rein <rick@openfortress.nl>
 */


#include "whoami.h"

#include <unistd.h>
#include <time.h>

#include <arpa/inet.h>

#include <tlspool/internal.h>

#include "trust.h"


/* Setup a cursor for a given key in the trust anchor database.  Setup the
 * first entry in trustdata, or return DB_NOTFOUND if none is available.
 */
int dba_trust_iterate (DBC *crs_trust, DBT *keydata, DBT *trustdata) {
	return crs_trust->get (crs_trust, keydata, trustdata, DB_SET);
}


/* Move the trust anchor database cursor to the next entry.  Setup this next
 * entry in trustdata, or return DB_NOTFOUND if none is available.
 */
int dba_trust_next (DBC *crs_trust, DBT *keydata, DBT *trustdata) {
	return crs_trust->get (crs_trust, keydata, trustdata, DB_NEXT_DUP);
}


/* Interpret a value in the trust anchor database.  We do not care about
 * the key at this point, just about providing the right information to
 * be able to match with the type of keyed value.
 *
 * The returned value is a TAD_STATUS_xxx value, 0 for _SUCCESS.
 * Timing aspects of pinned data are not taken into account yet.
 */
int trust_interpret (DBT *trustentry, uint32_t *flags, char **valexp, uint8_t **trustdata, int *trustdatalen) {
	size_t valexplen;
	uint8_t *trustentry__data = (uint8_t *) trustentry->data;
	if (trustentry->size < 6) {
		// No room for the flags and mininal valexplen 1 + NUL
		return TAD_STATUS_INVALID;
	}
	valexplen = strnlen (trustentry__data + 4, trustentry->size - 4);
	if (valexplen == 0) {
		// Empty string is a syntax error
		return TAD_STATUS_INVALID;
	}
	if (valexplen >= trustentry->size - 4) {
		// No terminating NUL character
		return TAD_STATUS_INVALID;
	}
	*flags = ntohl (* (uint32_t *) trustentry__data);
	*valexp = trustentry__data + 4;
	*trustdata    = trustentry__data + 4 + valexplen + 1;
	*trustdatalen = trustentry->size - 4 - valexplen - 1;
	return TAD_STATUS_SUCCESS;
}

/* Assuming a TAD_TYPE_PINNED_xxx, interpret any additional data to hold
 * up to two uint32 parameters:
 *  - a timestamp for the hard termination of the pinning (default never)
 *  - a timestamp after which the pinning may be replaced (default -0)
 *
 * This function returns a TAD_STATUS_xxx value, possibly _SUCCESS for ok.
 */
int trust_pinned_timing (uint8_t *trustdata, int trustdatalen) {
	time_t before = 0;
	time_t current;
	time_t expires;
	switch (trustdatalen) {
	case 8:
		before = htonl (* (uint32_t *) (trustdata + 4));
		// Continue into "case 4"
	case 4:
		expires = htonl (* (uint32_t *) (trustdata + 0));
		time (&current);
		if (current > expires) {
			return TAD_STATUS_EXPIRED;
		}
		if (current > expires - before) {
			return TAD_STATUS_REPLACEABLE;
		}
		// Continue into "case 0"
	case 0:
		// OK, by definition, in lieu of expiration timestamp
		return TAD_STATUS_SUCCESS;
	default:
		return TAD_STATUS_INVALID;
	}
}
