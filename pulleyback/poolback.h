/* pulleyback/poolback.h -- Backend from SteamWorks Pulley to TLS Pool.
 *
 * This is a backend for the Pulley component in SteamWorks, serving as
 * an output driver towards the databases of the TLS Pool.  This is meant
 * to enable LDAP-based configuration of the TLS Pool, so as to facilitate
 * provisioning of its security settings by a trusted upstream party.
 * 
 * From: Rick van Rein <rick@openfortress.nl>
 */


#include <stdint.h>

#include <db.h>


/* The "self" type for this API implementation.  This will be communicated
 * with the Pulley as the (void *) with the data for a backend instance.
 */
struct pulleyback_tlspool;


/* The mutexgroup is an abstract resource that cannot be claimed by more
 * than one syntactical occurrences; the same resource may however by
 * claimed by various entries, even in different positions in the syntax.
 *
 * When a keyword is found, the mutexgroup(s) in which it belongs are
 * claimed for that keyword occurrence, but when it has already been
 * claimed by another, a syntax error is raised.  After analysing all
 * syntax, a check is done if all required mutexgroups have been claimed.
 *
 * The special value MXG_NONE does not represent a mutex group, and
 * MXG_COUNT indicates the number of mutex groups except MXG_NONE.
 *
 * As an example, MXG_ROLE is claimed by the subtype= words for client,
 * server, peer but also by the args= word for role.  This means that the
 * role can only be supplied by one of the static words like
 * subtype="client,x509", or it can be supplied dynamically with
 * args="role", but not both.  In addition, it will be required for
 * type="localid" and type="trust", but not for type="disclose".
 */
enum mutexgroup {
	// The marker for an invalid value, end of list, uninitialised, ...
	MXG_NONE = -1,
	// Mutex keywords in the parameter lists
	MXG_CONFIG,
	MXG_TYPE,
	MXG_ARGS,
	MXG_SUBTYPE,
	// Mutex groups or, in case of dynamic provisioning, specific keywords
	MXG_ROLE,
	MXG_CREDTYPE,
	MXG_TRUSTKIND,
	// Specific keywords that must not occur more than once
	// (and that may be banned by other words incompatible with them)
	MXG_CLIENT,
	MXG_SERVER,
	MXG_PEER,
	MXG_X509,
	MXG_PGP,
	MXG_AUTHORITY,
	MXG_VALEXP,
	MXG_LOCALID,
	MXG_REMOTEID,
	MXG_PKCS11,
	MXG_CRED,
	MXG_CHAINED,
	// The number of mutex groups
	MXG_COUNT
};


/* A keyword descriptor is used while parsing a string.  It is setup with
 * sufficient mutexgroups to cover the lists for upcoming keywords, which
 * always ends with MGX_NONE.
 *
 * The descriptor contains a "claim string" which briefly describes the
 * syntactical occurrence of the claim, so that in case of a clash they
 * can both be claimed.
 *
 * Syntaxes contain a list of these keyword descriptors, ending with an
 * entry whose keyword is set to NULL; this entry is symbolically defined
 * as KEYWORD_LISTEND.
 *
 * There generally are different lists for the different places in the
 * syntax, all statically defined below.  Their type is logically
 * represented as keyword_syntax.
 */

struct keyword_descriptor {
	char *keyword;
	char *claim;
	enum mutexgroup resources [10];
};

#define KEYWORD_LISTEND { NULL, NULL, { MXG_NONE } }

typedef struct keyword_descriptor syntax_keywordlist [];



/* Tracking state for transactions.  These are used to administer what has
 * already been done to a transaction, to achieve idempotency with things
 * such as transaction failures.
 */
enum txnstate {
	TXN_NONE = 0,	// No current transaction (initial status)
	TXN_ACTIVE,	// Transaction is processing data
	TXN_ABORT,	// Transaction will not succeed
	TXN_SUCCESS	// Transaction is ready for commit
};


/* The general type of the database update functions.
 */
typedef int update_fun (struct pulleyback_tlspool *self, uint8_t **data, int rm);


/* The pb_tlspool structure holds handler information for the PulleyBack API.
 * 
 * The configuration information derived from Pulley Script:
 *  - config_file is the name of the configuration file, and might be reloaded
 *  - type is one of "disclose", "localid" or "trust" for the databases
 *  - subtypes contains flags 1 << MXG_xxx for configured subtype flags
 *  - args[] holds a MXG_NONE-terminated list of argument resources supplied
 *
 * The management information for the database and any current transaction:
 *  - The database environment handle
 *  - A database handle, for reading+writing, with transactions
 *  - The current transaction, or NULL if none is active
 */
struct pulleyback_tlspool {
	//
	// Parameters from Pulley Script, as supplied to pulleyback_open
	const char *config;
	const char *type;
	const char *valexp;
	uint32_t subtypes;
	enum mutexgroup args [MXG_COUNT + 1];
	//
	// Derived functions for this particular backend
	update_fun *update;
	//
	// Information loaded from the configuration file
	char *db_env;
	char *db_filename;
	//
	// Database management structures; where txn may be NULL if not open
	DB_ENV *env;
	DB     *db;
	DB_TXN *txn;
	u_int8_t txn_gid [DB_GID_SIZE];
	enum txnstate txn_state;
};





/* Parse all arguments to the backend function for the purpose of creating
 * a new output driver instance.  All the words must be recognised and all
 * the sublists ought to be as well, and in the end all the type-required
 * resources must have been defined.
 *
 * This function returns -1 on error, or 0 for success, in the latter case
 * it also configures the structure pointed at by data for later use.
 * In the data structure, only the parameters from the Pulley Script are
 * overwritten (and will fully be overwritten upon success).
 */
int parse_arguments (int argc, char *argv [], int varc,
				struct pulleyback_tlspool *self);


/* Parse the dynamic instantiation value of a parameter, if its self->args [i]
 * indicates that it is suitable for this.  This is currently only the case
 * with MXG_ROLE and MXG_CREDTYPE.  Instantiations are taken from the
 * syntax_subtype table, whose resources are ordered to accommodate that.
 *
 * On encountering an error, this function returns MXG_NONE; otherwise it
 * returns the recognised word, which is of the indicated type.
 *
 * Resource management has all been taken care of at compile time, so
 * that is trivially skipped during this run.
 */
enum mutexgroup parse_dynamic_argument (char *arg, enum mutexgroup dyntype);


/* Open a database environment and a database file.  Returns 0 for succes,
 * or -1 for error.
 */
int open_database (struct pulleyback_tlspool *self);


/* Close the database environment.
 */
void close_database (struct pulleyback_tlspool *self);


/* Update the disclose database, adding when rm is zero, removing otherwise.
 *
 * The key in the disclose database is always the remote identity.
 *
 * The data in the disclose database is always the disclosed local identity.
 *
 * One remote identity may have multiple local identities disclosed to it,
 * so removal is based on reproduction of both key and data; this is
 * possible because the Pulley reproduces the original data during removal.
 *
 * The function returns 1 on success, 0 on failure.
 */
int update_disclose (struct pulleyback_tlspool *self, uint8_t **data, int rm);


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
 *
 * The function returns 1 on success, 0 on failure.
 */
int update_localid (struct pulleyback_tlspool *self, uint8_t **data, int rm);


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
 *
 * The function returns 1 on success, 0 on failure.
 */
int update_trust (struct pulleyback_tlspool *self, uint8_t **data, int rm);

