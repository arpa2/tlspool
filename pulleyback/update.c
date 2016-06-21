/* pulleyback/update.c -- Collect data and update the database accordingly
 *
 * This is the actual interface to the database, harvesting information
 * from the API input, knowing that the syntax already prepared how and
 * where to find things.
 *
 * From: Rick van Rein <rick@openfortress.nl>
 */


#include <stdint.h>


#include "poolback.h"


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


/* Update the disclose database, adding when rm is zero, removing otherwise.
 * Documented in detail in poolback.h
 */
int update_disclose (struct pulleyback_tlspool *self, uint8_t **data, int rm) {
	TODO;
}

/* Update the localid database, adding when rm is zero, removing otherwise.
 * Documented in detail in poolback.h
 */
int update_localid (struct pulleyback_tlspool *self, uint8_t **data, int rm) {
	TODO;
}

/* Update the trust database, adding when rm is zero, removing otherwise.
 * Documented in detail in poolback.h
 */
int update_trust (struct pulleyback_tlspool *self, uint8_t **data, int rm) {
	TODO;
}

