/* pulleyback/parse.c -- Backend from SteamWorks Pulley to TLS Pool.
 *
 * This is a backend for the Pulley component in SteamWorks, serving as
 * an output driver towards the databases of the TLS Pool.  This is meant
 * to enable LDAP-based configuration of the TLS Pool, so as to facilitate
 * provisioning of its security settings by a trusted upstream party.
 * 
 * From: Rick van Rein <rick@openfortress.nl>
 */


#include <ctype.h>
#include <syslog.h>
#include <string.h>
#include <assert.h>

#include <syslog.h>

#include "poolback.h"



/* The syntax for the parameter names, covering:
 *  - "config" as a string reference to a TLS Pool configuration file
 *  - "type" as a string reference to a database type
 *  - "args" as a comma-separated list of arguments (count must match arg)
 *  - "subtype" as a comma-separated list of fields for all but type="disclose"
 */
static const syntax_keywordlist syntax_parameters = {
	{ "config",  "config parameter",  { MXG_CONFIG,  MXG_NONE } },
	{ "type",    "type parameter",    { MXG_TYPE,    MXG_NONE } },
	{ "args",    "args parameter",    { MXG_ARGS,    MXG_NONE } },
	{ "subtype", "subtype parameter", { MXG_SUBTYPE, MXG_NONE } },
	{ "valexp",  "valexp parameter",  { MXG_VALEXP,  MXG_NONE } },
	KEYWORD_LISTEND
};


/* The exclusions due to the "type" values is formulated as a syntax
 */
static const syntax_keywordlist exclusion_type = {
	{ "disclose", "disclose driver type", { MXG_SUBTYPE,
	                                        MXG_PKCS11,
	                                        MXG_CRED,
	                                        MXG_VALEXP,
	                                        MXG_CREDTYPE,
	                                        MXG_ROLE,
						MXG_TRUSTKIND,
	                                        MXG_NONE } },
	{ "localid",  "localid driver type",  { MXG_REMOTEID,
						MXG_TRUSTKIND,
	                                        MXG_NONE } },
	{ "trust",    "trust driver type",    { MXG_REMOTEID,
						MXG_LOCALID,
	                                        MXG_PKCS11,
	                                        MXG_NONE } },
	KEYWORD_LISTEND
};

/* In the same order as the exclusion_type string, the updated functions
 * for the recognised database types.
 */
static update_fun *update_type [] = {
	update_disclose,
	update_localid,
	update_trust
};


/* The syntax for the "args" word list.  The formatting is such that the
 * first (and only) MXG_ entry indicates the type if it happens to be one of
 * the words that can be instantiated -- namely, MXG_ROLE and MXG_CREDTYPE.
 */
static const syntax_keywordlist syntax_args = {
	{ "localid",  "localid argument",  { MXG_LOCALID, MXG_NONE } },
	{ "remoteid", "remoteid argument", { MXG_REMOTEID, MXG_NONE } },
	{ "pkcs11",   "pkcs11 argument",   { MXG_PKCS11, MXG_NONE } },
	{ "cred",     "cred argument",     { MXG_CRED, MXG_NONE } },
	{ "valexp",   "valexp argument",   { MXG_VALEXP, MXG_NONE } },
	{ "credtype", "credtype argument", { MXG_CREDTYPE, MXG_NONE } },
	{ "role",     "role argument",     { MXG_ROLE, MXG_NONE } },
	KEYWORD_LISTEND
};


/* The syntax for the "subtype" word list.  This is also used to parse
 * dynamically bound parameters for MXG_ROLE or MXG_CREDTYPE; there, it
 * uses the specific property that the first listed MXG_ is the instance
 * and the second listed MXG_ is the type of the entry.  The type must
 * match with the self->args entry's indication of a type, of course.
 */
static const syntax_keywordlist syntax_subtype = {
	{ "x509",      "x509 subtype",      { MXG_X509,
	                                      MXG_CREDTYPE,
	                                      MXG_NONE } },
	{ "openpgp",   "openpgp subtype",   { MXG_PGP,
	                                      MXG_CREDTYPE,
	                                      MXG_NONE } },
	{ "client",    "client subtype",    { MXG_CLIENT,
	                                      MXG_ROLE,
	                                      MXG_NONE } },
	{ "server",    "server subtype",    { MXG_SERVER,
	                                      MXG_ROLE,
	                                      MXG_NONE } },
	{ "peer",      "peer subtype",      { MXG_PEER,
	                                      MXG_ROLE,
	                                      MXG_CLIENT,
	                                      MXG_SERVER,
	                                      MXG_NONE } },
	{ "chained",   "chained subtype",   { MXG_CHAINED,
	                                      MXG_NONE } },
	{ "authority", "authority subtype", { MXG_AUTHORITY,
                                              MXG_TRUSTKIND,
	                                      MXG_NONE } },
	KEYWORD_LISTEND
};


/* The required resources for the various types
 */
static const enum mutexgroup typereq_any [] = {
	MXG_TYPE, MXG_ARGS,
	MXG_NONE
};
static const enum mutexgroup typereq_disclose [] = {
	MXG_TYPE, MXG_ARGS, MXG_LOCALID, MXG_REMOTEID,
	MXG_NONE
};
static const enum mutexgroup typereq_localid [] = {
	MXG_TYPE, MXG_ARGS, MXG_LOCALID, MXG_PKCS11, MXG_CRED, MXG_CREDTYPE, MXG_ROLE,
	MXG_NONE
};
static const enum mutexgroup typereq_trust [] = {
	MXG_TYPE, MXG_ARGS, MXG_CRED, MXG_VALEXP, MXG_CREDTYPE, MXG_ROLE,
	MXG_TRUSTKIND,
	MXG_NONE
};


/* Chase for a string's keyword_description.  The word is supposed to
 * end in a given terminal character although, if this is a comma, the
 * end of a string will also match (but comma lists may not be empty).
 *
 * The returned value indicates success with a non-negative value, or
 * syntax error with -1.  The positive values returned is the index in
 * the keyword_descriptor array passed in.
 *
 * Searching starts at the provided (pointed-at) offset in the string,
 * and that offset will be incremented to point beyond the keyword,
 * though never beyond the end-of-string NUL character.
 *
 * This routine updates the resource claims in the provided resource
 * array, and reports on syslog() when it finds a conflict; in that
 * case, it also returns an error.
 *
 * It is permitted to pass NULL for resources; no check on conflicts
 * will then be made; this is useful during dynamic parsing, after
 * the static analysis has already taken care of resource conflicts
 * and all that is required to live up to it is recognising keywords
 * of the proper type.
 */
static int chase_keyword_descriptor (const struct keyword_descriptor *kd,
					char *resources [MXG_COUNT],
					const char *text, int *offset) {
	int kdofs;
	const enum mutexgroup *mtg;
	if (text [*offset] == '\0') {
		syslog (LOG_ERR, "Unexpected end of string in %s", text);
		return -1;
	}
	for (kdofs = 0; kd->keyword != NULL; kdofs++, kd++) {
		int kwl = strlen (kd->keyword);
		if ((memcmp (kd->keyword, text + *offset, kwl) == 0) && (isalnum (text [*offset + kwl]) == 0)) {
			// We found a match -- check for resource clashes
			if (resources != NULL) {
				for (mtg = kd->resources; *mtg != MXG_NONE; mtg++) {
					if (resources [*mtg] != NULL) {
						syslog (LOG_ERR, "You cannot specify both %s and %s", resources [*mtg], kd [kdofs].claim);
						return -1;
					}
					resources [*mtg] = kd->claim;
				}
			}
			// Return successfully
			*offset += kwl;
			return kdofs;
		}
	}
	syslog (LOG_ERR, "Unrecognised keyword at offset %d in %s", offset, text);
	return -1;
}


/* Parse a comma-separated list of entries and store them in-order in a
 * sequence of the order numbers.  Return -1 on error, or otherwise the
 * number of entries that were parsed successfully.
 *
 * The offset points to the position in the string, and this will be
 * updated in case of success.  Also, the resources will be used to
 * collect potential clashes between mutually exclusive resource claims.
 */
static int parse_wordlist (const struct keyword_descriptor *kd,
					int kdidx [MXG_COUNT],
					char *resources [MXG_COUNT],
					const char *text, int *offset) {
	int rv;
	int kdidx_count = 0;
	char comma;
	while (1) {
		rv = chase_keyword_descriptor (kd, resources, text, offset);
		if (rv < 0) {
			return -1;
		}
		if (kdidx_count >= MXG_COUNT) {
			syslog (LOG_ERR, "More than %d words in %s", kdidx_count, text);
			return -1;
		}
		// rv is the number of the kd entry;
		// Now place its first resource into kdidx
		kdidx [kdidx_count++] = kd [rv].resources [0];
		comma = text [*offset];
		if (comma != ',') {
			break;
		}
		(*offset)++;
	}
	if (comma != '\0') {
		syslog (LOG_ERR, "Unexpected character '%c' at offset %d in %s", comma, *offset, text);
		return -1;
	}
	return kdidx_count;
}


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
				struct pulleyback_tlspool *self) {
	int argi;
	int parsed;
	int num_args = 0;
	int num_subtypes = 0;
	int list_subtypes [MXG_COUNT + 1];
	char *resources [MXG_COUNT];
	int argofs;
	const enum mutexgroup *minreq;
	//
	// Initialise parsing structures
	self->config = NULL;
	self->type = NULL;
	self->subtypes = 0;
	self->valexp = NULL;
	assert (sizeof (self->args   ) == sizeof (int) * (MXG_COUNT + 1));
	assert (sizeof (list_subtypes) == sizeof (int) * (MXG_COUNT + 1));
	for (argi=0; argi < MXG_COUNT + 1; argi++) {
		self->args    [argi] =
		list_subtypes [argi] = MXG_NONE;
	}
	memset (resources, 0, sizeof (resources));  // all NULL strings
	//
	// Pick up all the words and word lists, while scoring resources
	for (argi = 1; argi < argc; argi++) {
		argofs = 0;
		parsed = chase_keyword_descriptor (
					syntax_parameters,
					resources,
					argv [argi], &argofs);
		if ((parsed >= 0) && (argv [argi] [argofs] != '=')) {
			syslog (LOG_ERR, "No equals sign in %s", argv [argi]);
			parsed = -1;
		}
		argofs++;  // Skip '=' sign
		if (parsed == -1) {
			return -1;
		}
		switch (syntax_parameters [parsed].resources [0]) {
		case MXG_CONFIG:
			self->config = argv [argi] + argofs;
			parsed = (*self->config) ? 0 : -1;;
			break;
		case MXG_TYPE:
			parsed = chase_keyword_descriptor (
					exclusion_type,
					resources,
					argv [argi], &argofs);
			minreq = typereq_any;
			if (parsed >= 0) {
				self->type = exclusion_type [parsed].keyword;
				self->update =  update_type [parsed];
				if (*exclusion_type [parsed].keyword == 'd') {
					minreq = typereq_disclose;
				} else if (*exclusion_type [parsed].keyword == 'l') {
					minreq = typereq_localid;
				} else if (*exclusion_type [parsed].keyword == 't') {
					minreq = typereq_trust;
				}
			}
			break;
		case MXG_ARGS:
			parsed = num_args = parse_wordlist (
					syntax_args,
					self->args,
					resources,
					argv [argi], &argofs);
			break;
		case MXG_SUBTYPE:
			parsed = num_subtypes = parse_wordlist (
					syntax_subtype,
					list_subtypes,
					resources,
					argv [argi], &argofs);
			break;
		case MXG_VALEXP:
			self->valexp = argv [argi] + argofs;
		default:
		case -1:
			parsed = -1;
			break;
		}
		if (parsed == -1) {
			return -1;
		}
	}
	//
	// Compare the number of args entries to the number supplied in varc
	if (num_args != varc) {
		syslog (LOG_ERR, "You listed %d args keywords, but provided %d variables", num_args, varc);
		parsed = -1;
	}
	//
	// Ensure that minimum requirements are met
	while (*minreq != MXG_NONE) {
		if (resources [*minreq] == NULL) {
			//TODO// Would be nice to say what is missing...
			syslog (LOG_ERR, "Missing resource in output handler");
			parsed = -1;
		}
		minreq++;
	}
	if (parsed == -1) {
		return -1;
	}
	//
	// Harvest the flags for the subtypes found
	assert (8 * sizeof (self->subtypes) <= 1 << MXG_COUNT);
	for (argi = 0; argi < num_subtypes; argi++) {
		self->subtypes |= ( 1 << list_subtypes [argi] );
		assert ((self->subtypes & (1 << list_subtypes [argi])) != 0);
	}
	return 0;
}


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
enum mutexgroup parse_dynamic_argument (char *arg, enum mutexgroup dyntype) {
	int argofs = 0;
	int ok = 1;
	int rv;
	assert ((dyntype == MXG_ROLE) || (dyntype == MXG_CREDTYPE));
	rv = chase_keyword_descriptor (	syntax_subtype,
					NULL  /* no resources */ ,
					arg, &argofs);
	ok = ok && (rv >= 0);
	ok = ok && (arg [argofs] == '\0');
	ok = ok && (syntax_subtype [rv].resources [1] == dyntype);
	return  ok? syntax_subtype [rv].resources [0]: MXG_NONE;
}

