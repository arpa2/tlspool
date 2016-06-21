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


/* Update the disclose database, adding when rm is zero, removing otherwise.
 *
 * The key in the disclose database is always the remote identity.
 *
 * The data in the disclose database is always the disclosed local identity.
 *
 * One remote identity may have multiple local identities disclosed to it,
 * so removal is based on reproduction of both key and data; this is
 * possible because the Pulley reproduces the original data during removal.
 */
void update_disclose (struct pulleyback_tlspool *self, uint8_t **data, int rm) {
	TODO;
}

/* Update the localid database, adding when rm is zero, removing otherwise.
 * 
 * The key in the localid database is always the local identity.  It is
 * possible to have multiple entries with the same localid, and removal
 * requires a match with the flags field (which can be reproduced based
 * on the repeated input to this function provided by the Pulley).
 *
 * The data in the localid database consists of flags, an optional string
 * with a pkcs11: URI or a validation expression, and a public credential.
 *  - for X.509 and PGP signers, the credential is the binary key material
 *  - for validation expressions, there is no pkcs11: URI but a valexp string
 */
void update_localid (struct pulleyback_tlspool *self, uint8_t **data, int rm) {
	TODO;
}

/* Update the trust database, adding when rm is zero, removing otherwise.
 *
 * The key into the trust database is a binary form dependent on the data
 * described:
 *  - an X.509 signer uses the issuer key identity;
 *  - a PGP signer uses the 64-bit key identifier based on sha1;
 *  - a pinning entry uses the sha256 of the pinned credential.
 *
 * The data in the trust database consists of flags, a validation expression
 * and sometimes a public credential.
 *  - for X.509 signers, the credential is the signer's DER certificate
 *  - for PGP signers, the credential is the signer's binary public key
 *  - for pinning entries, no credential is provided
 *
 * The database may have multiple entries, even of the same type.  Removal
 * is only possible for accurate matches, which is not a problem as the
 * information can be reproduced from the same input coming out of the
 * Pulley.
 */
void update_trust (struct pulleyback_tlspool *self, uint8_t **data, int rm) {
	TODO;
}

