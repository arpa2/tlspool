/* tlspool/localid.h -- Map the keys of local identities to credentials */


/*
 * Lookup local identities from a BDB database.  The identities take the
 * form of a NAI, and are the keys for a key-values lookup.  The outcome
 * may offer multiple values, each representing an identity.  The general
 * structure of a value is:
 *
 * - 4 netbytes, a flags field for local identity management (see LID_xxx below)
 * - NUL-terminated string with a pkcs11 URI [ draft-pechanec-pkcs11uri ]
 * - Binary string holding the identity in binary form
 *
 * There may be prefixes for generic management, but these are not made
 * available to this layer.
 */


#define LID_HDRSZ	(MGT_HDRSZ + 4)


#define LID_TYPE_MASK	0x000000ff	/* Separate out the LID_TYPE_xxx bits */
#define LID_TYPE_ANY	0x000000ff	/* No filter, permit anything */
#define LID_TYPE_X509	0x00000001	/* X.509 certificate, DER-encoded */
#define LID_TYPE_PGP	0x00000002	/* OpenPGP public key, binary form */
#define LID_TYPE_SRP	0x00000003	/* No data, flags existence */
#define LID_TYPE_KRB5	0x00000004	/* Ticket */

#define LID_ROLE_MASK	0x00000300	/* Separate out the LID_ROLE_xxx bits */
#define LID_ROLE_CLIENT	0x00000100	/* This may be used for clients */
#define LID_ROLE_SERVER	0x00000200	/* This may be used for servers */
#define LID_ROLE_BOTH	0x00000300	/* This may be used for both roles */
#define LID_ROLE_NONE	0x00000000	/* This may be used for neither role */


/* Impose a practial upper bound to the lenght of a DoNAI, a domain-or-NAI.
 * This is important to avoid overzealous allocations and subsequent buffer
 * or stack overflows.  Sigh, we live in a world where networks can carry
 * the size between memory segments in a brief time.
 */
#define DONAI_MAXLEN 512


/* Create an iterator for a given localid value.  Use keys from dhb_lid.
 * The first value is delivered; continue with dbcred_iterate_next().
 *
 * The cursor must have been opened on dbh_localid within the desired
 * transaction context; the caller must close it after iteration.
 *
 * The value returned is only non-zero if a value was setup.
 * The DB_NOTFOUND value indicates that the key was not found.
 */
int dbcred_iterate_from_localid (DBC *cursor, char *localid, DBT *keydata, DBT *creddata);

/* Construct an iterator for a given remoteid value.
 * Apply stepwise generalisation to selectors to find the most concrete match.
 * The first value is delivered; continue with dbcred_iterate_next().
 *
 * The started iteration is a nested iteration over dbh_disclose for the
 * given remoteid, and inside that an iteration over dbh_localid for the
 * localid values that this gave.  This means that two cursors are needed,
 * both here and in the subsequent dbcred_iterate_next() calls.
 *
 * The cursors crs_disclose and crs_localid must have been opened on
 * dbh_disclose and dbh_localid within the desired transaction context;
 * the caller must close them after iteration.
 *
 * The value returned is zero if a value was setup; otherwise an error code.
 * The DB_NOTFOUND value indicates that no selector matching the remoteid
 * was found in dbh_disclose.
 */
int dbcred_iterate_from_remoteid (DBC *crs_disclose, DBC *crs_localid, DBT *discpatn, DBT *keydata, DBT *creddata);

/* Move an iterator to the next credential data value.  When done, the value
 * returned should be DB_NOTFOUND.
 *
 * The outer cursor (for dbh_disclose) is optional, and is only used when
 * the prior call was from dbcred_iterate_from_remoteid().
 *
 * The optional discpatn must be supplied only when dbh_disclose is provided.
 * It holds the key value for the dbh_disclose outer cursor.
 *
 * The keydata will be filled with the intermediate key when dbh_disclose is
 * provided.  It is also used to match the next record with the current one.
 *
 * The value returned is zero if a value was setup; otherwise an error code.
 * The DB_NOTFOUND value indicates that no further duplicate was not found.
 */
int dbcred_iterate_next (DBC *opt_crs_disclose, DBC *crs_localid, DBT *opt_discpatn, DBT *keydata, DBT *creddata);



/* Interpret the credentials structure found in dbh_localid.
 * This comes down to splitting the (data,size) structure into fields:
 *  - a 32-bit flags field
 *  - a char * sharing the PKCS #11 private key location
 *  - a (data,size) structure for the public credential
 * The function returns non-zero on success (zero indicates syntax error).
 */
int dbcred_interpret (DBT *creddata, uint32_t *flags, char **p11priv, uint8_t **pubdata, int *pubdatalen);


/* A donai is a structure holding either user@domain.name or domain.name.
 * A selector is a simple pattern that can match with a donain, by stripping
 * local components.  For instance user@domain.name or @domain.name or @.name
 * or @. to match with user@domain.name; and, for instance domain.name or
 * .name or . to match with domain.name.
 */

struct userdomain {
	char *user;	/* not NUL-terminated; user==NULL for no @ at all */
	int userlen;	/* valid if user!=NULL; userlen<0 in selector_t for 0 */
	char *domain;	/* not '', not NULL, start . signifies a pattern */
};


typedef struct userdomain donai_t;  /* user != '' AND *domain != '.' */

typedef struct userdomain selector_t;  /* IF user == '' THEN *domain != '.' */


/* Iterate over selector values that would generalise the donai.  The
 * selector_t shares data from the donai, so it allocates no internal
 * storage and so it can be dropped at any time during the iteration.
 * Meanwhile, the donai must not drop storage before iteration stops.
 *
 * The value returned is only non-zero if a value was setup.
 */
int selector_iterate_init (selector_t *iterator, donai_t *donai);
int selector_iterate_next (selector_t *iterator);

/* Print a donai or iterated selector to the given text buffer.  The
 * text will be precisely the same as the originally parsed text.  An
 * iterator may deliver values that are shorter, not longer.  The value
 * returned is the number of bytes written.  No trailing NUL character
 * will be written.
 */
int donai_iterate_memput (char *selector_text, donai_t *iterator);


/* Check if a selector is a pattern that matches the given donai value.
 * The value returned is non-zero for a match, zero for a non-match.
 */
int donai_matches_selector (donai_t *donai, selector_t *pattern);


/* Fill a donai structure from a stable string. The donai will share parts
 * of the string.
 */
donai_t donai_from_stable_string (char *stable);

