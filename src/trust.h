/* trust.h -- Trust anchor database structures, such as flags.
 *
 * These fields and flags are used for the trust database in the TLS Pool.
 * The key is "something binary" that summarises "what is being sought" and
 * then multiple entries may live under that key.  The initial flag field
 * holds a type subfield that indicates an interpretation of the key, so
 * different reasons for finding the key cannot clash.  It is the intention
 * to iterate over the entries one by one.
 *
 * Each entry (that is, each separate value under a key) has a validation
 * expression for use with validate.c, which will be incorporated for any
 * use under the trust anchors.
 *
 * From: Rick van Rein <rick@openfortress.nl>
 */


/* TAD is the Trust Anchor Database.  It header size is well-defined.
 */
#define TAD_HDRSZ	4

/* The first entry in each value is a flag word, including type information.
 * The values defined here _happen_ to match several of the LID_ values, but
 * should not be used with them.
 */
#define TAD_TYPE_MASK	0x000000ff	/* Separate out the TAD_TYPE_xxx bits */
// no use for TAD_TYPE_ANY
#define TAD_TYPE_X509	0x00000001	/* X.509 trusted root certificate */
#define TAD_TYPE_PGP	0x00000002	/* OpenPGP trusted direct signer */
// no use for TAD_TYPE_SRP
// no use for TAD_TYPE_KRB5 (yet)

#define TAD_ROLE_MASK	0x00000300	/* Separate out the TAD_ROLE_xxx bits */
#define TAD_ROLE_CLIENT	0x00000100	/* Clients may trust this anchor */
#define TAD_ROLE_SERVER	0x00000200	/* Servers may trust this anchor */
#define TAD_ROLE_BOTH	0x00000300	/* Anyone  may trust this anchor */
#define TAD_ROLE_NONE	0x00000000	/* No-one  may trust this anchor */

#define TAD_TYPE_REVOKE_MASK	0x00000400	/* Any form of revocation */
#define TAD_TYPE_REVOKE_X509	0x00000401	/* X.509 revocation list */
#define TAD_TYPE_PINNED_MASK	0x00000800	/* Any form of pinned cred */
#define TAD_TYPE_PINNED_X509	0x00000801	/* Pinned X.509 end-cert */
#define TAD_TYPE_PINNED_PGP	0x00000802	/* Pinned OpenPGP end-key */

#define TAD_NOTROOT	0x00001000	/* Trusted, though not a root anchor */

/* The second entry is a NUL-terminated validation expression.  The shortest
 * forms are "0" (hexadecimal 0x30 0x00) and "1" (hex 0x31 0x00) which stand
 * for "always good as far as I'm concerned" and "never any good"; the latter
 * might be used to refrain from using this trust anchor, though it might be
 * overruled by other entries, so it is only powerful in the absense of other
 * reasons for validation.  There is no functional distinction between setting
 * a validation expression to "0" or removing its entry.  Having said that,
 * tools may want to temporarily disable expressions "..." by changing them to
 * "(&0...)" though that would be a hack, as it assumes a single editing
 * utility on the validation expressions.
 */

/* The third entry depends on the TAD_TYPE_xxx value.
 *
 * For TAD_TYPE_X509, the X.509 trust anchor certificate follows in DER format
 * For TAD_TYPE_PGP, the trusted direct signing PGP key in binary format
 * For TAD_TYPE_REVOKE_X509, there are 2 timestamps and any number of
 *	DER-encoded CertificateSerialNumber (a.k.a. INTEGER) fields encoded
 *	in DER which is simply concatenated to the timestamps.  The first
 *	timestamp represents the time of the revocation list, the second is
 *	either less-or-equal (for instance, 0), or it is a timestamp for the
 *	next revocation update.
 * For TAD_TYPE_PINNED_X509 and TAD_TYPE_PINNED_PGP, there are 0, 1 or 2
 *	timestamps in 32-bit seconds-since-UTC-epoch format, which are,
 *	in order of appearance and only _when_ they appear, and otherwise
 *	the default behaviour kicks in:
 *	 * the 1st represents the cut-off time of the validity (otherwise
 *	   infite), usually filled with a certificate's end-of-validity time
 *	 * the 2nd represents a configurable number of seconds (default 0)
 *	   before the cut-off time when it is possible to silently roll to
 *	   another pinned value, but only once.  This is useful to deal with
 *	   regular updates to (server) certificates in a pragmatic manner.
 *	   After the 1st cut-off time has passed, this is always possible.
 */


/* The trust anchor status values, usable as return values.
 */
#define TAD_STATUS_SUCCESS	0
#define TAD_STATUS_NOTFOUND	1
#define TAD_STATUS_INVALID	2
#define TAD_STATUS_REPLACEABLE	3	/* Used with pinned data */
#define TAD_STATUS_EXPIRED	4	/* Used with pinned data */

/* Setup a cursor for a given key in the trust anchor database.  Setup the
 * first entry in trustdata, or return DB_NOTFOUND if none is available.
 */
int dba_trust_iterate (DBC *crs_trust, DBT *keydata, DBT *trustdata);

/* Move the trust anchor database cursor to the next entry.  Setup this next
 * entry in trustdata, or return DB_NOTFOUND if none is available.
 */
int dba_trust_next (DBC *crs_trust, DBT *keydata, DBT *trustdata);

/* Interpret a value in the trust anchor database.  We do not care about
 * the key at this point, just about providing the right information to
 * be able to match with the type of keyed value.
 *
 * The returned value is a TAD_STATUS_xxx value, 0 for _SUCCESS.
 * Timing aspects of pinned data are not taken into account yet.
 */
int trust_interpret (DBT *trustentry, uint32_t *flags, char **valexp, uint8_t **trustdata, int *trustdatalen);

/* Assuming a TAD_TYPE_PINNED_xxx, interpret any additional data to hold
 * up to two uint32 parameters:
 *  - a timestamp for the hard termination of the pinning (default never)
 *  - a timestamp after which the pinning may be replaced (default -0)
 *
 * This function returns a TAD_STATUS_xxx value, possibly _SUCCESS for ok.
 */
int trust_pinned_timing (uint8_t *trustdata, int trustdatalen);

