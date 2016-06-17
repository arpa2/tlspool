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
#define LID_TYPE_KRB5	0x00000004	/* Kerberos5 ticket */
#define LID_TYPE_VALEXP	0x00000005	/* Validation expression in PKCS #11 */

#define LID_TYPE_MIN	LID_TYPE_X509
#define LID_TYPE_MAX	LID_TYPE_VALEXP
#define LID_TYPE_OFS	LID_TYPE_MIN
#define LID_TYPE_CNT	(1 + LID_TYPE_MAX - LID_TYPE_MIN)

#define LID_ROLE_MASK	0x00000300	/* Separate out the LID_ROLE_xxx bits */
#define LID_ROLE_CLIENT	0x00000100	/* This may be used for clients */
#define LID_ROLE_SERVER	0x00000200	/* This may be used for servers */
#define LID_ROLE_BOTH	0x00000300	/* This may be used for both roles */
#define LID_ROLE_NONE	0x00000000	/* This may be used for neither role */

#define LID_NO_PKCS11	0x00001000	/* No prefixed PKCS #11 URI + NUL */
#define LID_CHAINED	0x00002000	/* Credential isa type-specific chain */
//TODO// Encode LID_NEEDS_CHAIN support
#define LID_NEEDS_CHAIN	0x00004000	/* Chain certs are in central storage */


/* Impose a practial upper bound to the lenght of a DoNAI, a domain-or-NAI.
 * This is important to avoid overzealous allocations and subsequent buffer
 * or stack overflows.  Sigh, we live in a world where networks can carry
 * the size between memory segments in a brief time.
 */
#define DONAI_MAXLEN 512


/* A donai is a structure holding either user@domain.name or domain.name.
 * A selector is a simple pattern that can match with a donain, by stripping
 * local components.  For instance user@domain.name or @domain.name or @.name
 * or @. to match with user@domain.name; and, for instance domain.name or
 * .name or . to match with domain.name.
 */

struct userdomain {
	char *user;	/* not NUL-terminated; user==NULL for no @ at all */
	int userlen;	/* valid if user!=NULL; userlen<0 in selector_t for 0 */
	char *domain;	/* not NULL, start . signifies a pattern */
	int domlen;	/* always >0 */
};


typedef struct userdomain donai_t;  /* (user==NULL OR userlen>0) AND *domain!='.' */

typedef struct userdomain selector_t;  /* userlen<0 should be read as userlen==0 */



/* Setup a clean DBT data handle, so it can withstand dbt_free().
 */
static inline void dbt_init_empty (DBT *dbt) {
	memset (dbt, 0, sizeof (DBT));
}

/* Setup a DBT data handle to point to a pre-allocated, fixed-size
 * data buffer that will be used throughout the use of the handle.
 * Cleanup is not necessary, but the buffer must not be cleared
 * before the last use of the data handle.
 */
static inline void dbt_init_fixbuf (DBT *dbt, void *buffer, u_int32_t bufsize) {
	bzero (dbt, sizeof (DBT));
	dbt->data = buffer;
	dbt->size =
	dbt->ulen = bufsize;
	dbt->flags |= DB_DBT_USERMEM;
}

/* Setup a DBT data handle for malloc() by the database, and free() by the
 * calling program.
 * Cleanup with dbt_free() or dbt_store() is needed after every lookup
 * that succeeded.
 */
static inline void dbt_init_malloc (DBT *dbt) {
	bzero (dbt, sizeof (DBT));
	dbt->flags |= DB_DBT_MALLOC;
}

/* Free the DBT data handle that was setup with dbt_init_malloc().  This
 * or dbt_store() must be called after every successfully returned data
 * item.
 */
static inline void dbt_free (DBT *dbt) {
	/* assert (dbt->flags & DB_DBT_MALLOC); */
	if (dbt->data) {
		free (dbt->data);
	}
	dbt->data = NULL;
}

/* Store the DBT data handle's data into external structures, moving both
 * the data pointer and size.  The data handle must have been setup with
 * dbt_init_malloc().  Afterwards, clear the data handle for use in
 * another iteration.
 */
static inline void dbt_store (DBT *dbt, pool_datum_t *output) {
	/* assert (dbt->flags & DB_DBT_MALLOC); */
	output->data = dbt->data;
	output->size = dbt->size;
	dbt->data = NULL;
}


/* Create an iterator for a given localid value.  Use keys from dhb_lid.
 * The first value is delivered; continue with dbcred_iterate_next().
 *
 * The cursor must have been opened on dbh_localid within the desired
 * transaction context; the caller must close it after iteration.
 *
 * The value returned is only non-zero if a value was setup.
 * The DB_NOTFOUND value indicates that the key was not found.
 */
db_error dbcred_iterate_from_localid (DBC *cursor, DBT *keydata, DBT *creddata);

/* Construct an iterator for a given remoteid selector.  Apply stepwise
 * generalisation to find the most concrete match.  The first value found
 * is delivered; continue with dbcred_iterate_next().
 *
 * The remotesel value in string representation is the key to discpatn,
 * forming the initial disclosure pattern.  This key should be setup with
 * enough space to store the pattern (which is never longer than the original
 * remoteid) plus a terminating NUL character.
 *
 * Note that remotesel already has the first value activated, usually the
 * same as the remoteid.  This is assumed to be available, so don't call
 * this function otherwise.  In practice, this is hardly a problem; any
 * valid remoteid will provide a valid selector whose first iteration is to
 * repeat the remoteid.  Failure to start even this is a sign of a syntax
 * error, which is good to be treating separately from not-found conditions.
 *
 * The started iteration is a nested iteration over dbh_disclose for the
 * pattern found, and inside that an iteration over dbh_localid for the
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
db_error dbcred_iterate_from_remoteid_selector (DBC *crs_disclose, DBC *crs_localid, selector_t *remotesel, DBT *discpatn, DBT *keydata, DBT *creddata);

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
int dbcred_interpret (pool_datum_t *creddata, uint32_t *flags, char **p11priv, uint8_t **pubdata, int *pubdatalen);


/* Iterate over selector values that would generalise the donai.  The
 * selector_t shares data from the donai, so it allocates no internal
 * storage and so it can be dropped at any time during the iteration.
 * Meanwhile, the donai must not drop storage before iteration stops.
 *
 * The value returned is only non-zero if a value was setup.
 */
int selector_iterate_init (selector_t *iterator, donai_t *donai);
int selector_iterate_next (selector_t *iterator);

/* Retrieve flags from the credentials structure found in dbh_localid.
 * The function returns non-zero on success (zero indicates syntax error).
 */
int dbcred_flags (DBT *creddata, uint32_t *flags);

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
 * of the string.  The function can also be used to construct a selector
 * from a string; their structures are the same and the syntax is not
 * parsed to ensure non-empty usernames and non-dot-prefixed domain names.
 */
donai_t donai_from_stable_string (char *stable, int stablelen);

