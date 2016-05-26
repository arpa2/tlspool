/* tlspool/online.c -- TLS pool online/live validation logic
 *
 * This module had to introduce various external dependencies:
 *  - LDAP (for the global directory)
 *  - Certificate DER parsing (for DANE, to find SubjectPublicKeyInfo)
 *  - GnuTLS (for hashing, for DANE)
 */


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


#include <stdlib.h>
#include <stdint.h>

#include <assert.h>
#include <syslog.h>

#include <sys/types.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#define LDAP_DEPRECATED 1
#include <ldap.h>

#include <unbound.h>
#include <ldns/ldns.h>

#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>

#include <quick-der/api.h>

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


/* The data structure that collects information while going:
 *  - the user-passed information: rid, and data/len to check
 *  - the _service._protocol prefix for an SRV record
 *  - the hostname visited from an SRV record
 *  - the port number from an SRV record
 *  - a file descriptor for a server conncetion
 *  - the TLSA data found through DANE
 */
typedef struct online_data {
	// User-passed data
	char *rid;
	uint8_t *data;
	uint16_t len;
	// SRV record info
	struct ub_result *dnssrv;
	uint16_t dnssrv_next;
	char *srv_prefix;  // NULL when using a direct host name
	char *srv_server;  // For direct host name, shares domain part of rid
	uint16_t srv_port; // host byte order; default port for direct host
	// A/AAAA record info
	struct ub_result *dnsip;
	int dnsip_mustsecure;
	char *dnsip_name;
	uint8_t *dnsip_addr;
	int dnsip_addrfam;
	int dnsip_next;
	// TLSA record info
	struct ub_result *dnstlsa;
	uint16_t dane_certusage;
	uint16_t dane_selector;
	uint16_t dane_matchtype;
	uint8_t *dane_certdata;
	int dane_certdata_len;
	int dnstlsa_next;
	// Server connection
	int cnx;
	// LDAP connection information
	LDAP *ldap;
	LDAPMessage *ldap_attr_search;
	LDAPMessage *ldap_attr;
} online_data_st, *online_data_t;


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
 *  - having a "first" routine that returns _SUCCESS when data was found
 *  - having a "next" routine if multiplicity is possible, _SUCCESS until end
 *  - having a "clean" routine, if needed, to cleanup after "first", "next"
 *  - having parameters to pass to the "first" and "next" routines
 *  - maintaining a cursor as a (crs_t) with child-value (val_t)
 *  - having potential follow-up steps for each "first" and "next" finding
 *  - having potential alt strategies if a branch returns ONLINE_NOTFOUND
 */
struct online_profile {
	struct online_profile *altstrat;
	struct online_profile *child;
	int  (*eval ) (          online_data_t, val_t, char *);
	int  (*first) (crsval_t, online_data_t, val_t, char *);
	int  (*next ) (crsval_t, online_data_t, val_t);
	void (*clean) (crsval_t, online_data_t, val_t);
	uint16_t crslen;	/* TODO - crslen replaceable by depth/crs_t */
	char *param;
	uint16_t depth;		/* Never define, autocomputed when set to 0 */
};
typedef struct online_profile online_profile_t;

int online2success_enforced (int online) {
	return online == ONLINE_SUCCESS;
}

int online2success_optional (int online) {
	return online != ONLINE_INVALID;
}


/* Global variables for this module */

// Unbound context
static struct ub_ctx *ubctx = NULL;

// LDAP timeout setting
static struct timeval ldap_timeout = {
	.tv_sec = 2,
	.tv_usec = 0,
};

// Quick-DER WALK to a Certificate's SubjectPublicKeyInfo
static const derwalk to_subjectpublickeyinfo [] = {
	DER_WALK_ENTER | DER_TAG_SEQUENCE,	// Certificate
	DER_WALK_ENTER | DER_TAG_SEQUENCE,	// TBSCertificate
	DER_WALK_OPTIONAL,
	DER_WALK_SKIP  | DER_TAG_CONTEXT(0),	// [0] Version DEFAULT v1
	DER_WALK_SKIP  | DER_TAG_INTEGER,	// serialNumber
	DER_WALK_SKIP  | DER_TAG_SEQUENCE,	// signature
	DER_WALK_SKIP  | DER_TAG_SEQUENCE,	// issuer CHOICE { SEQUENCE }
	DER_WALK_SKIP  | DER_TAG_SEQUENCE,	// validity SEQUENCE { ... }
	DER_WALK_SKIP  | DER_TAG_SEQUENCE,	// subject CHOICE { SEQUENCE }
	DER_WALK_END				// subjectPublicKeyInfo
};


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
static int online_iterate (online_profile_t *prf, online_data_t dta,
				val_t hdl) {
	int retval = ONLINE_NOTFOUND;
	int retval_invalid = 0;
	assert (prf != NULL);
	if (prf->eval != NULL) {
		retval = prf->eval (dta, hdl, prf->param);
	}
	while (retval == ONLINE_NOTFOUND) {
		crsval_st cursor;
		assert (prf->first != NULL);
		//OLD// int todo = (prf->first != NULL) && prf->first (&cursor, dta, hdl, prf->param);
		retval = prf->first (&cursor, dta, hdl, prf->param);
		//OLD// while (todo) {
		while (retval == ONLINE_SUCCESS) {
			retval = online_iterate (prf->child, dta, &cursor.val);
			//OLD// todo = (retval == ONLINE_NOTFOUND) &&
				//OLD// (prf->next != NULL) &&
				//OLD// prf->next (&cursor, dta, hdl);
			if (retval != ONLINE_NOTFOUND) {
				break;
			}
			if (prf->next == NULL) {
				break;
			}
			retval = prf->next (&cursor, dta, hdl);
		}
		if (prf->clean != NULL) {
			prf->clean (&cursor, dta, hdl);
		}
		if (retval != ONLINE_SUCCESS) {
			prf = prf->altstrat;
			if (prf == NULL) {
				break;
			}
			retval_invalid = 1;
			retval = ONLINE_NOTFOUND;
		}
	}
	if ((retval == ONLINE_SUCCESS) && (retval_invalid > 0)) {
		retval = ONLINE_INVALID;
	}
	return retval;
}

int online_run_profile (online_profile_t *prf,
				char *rid, uint8_t *data, uint16_t len) {
	online_data_st dta = { 0 };
	dta.rid = rid;
	dta.data = data;
	dta.len = len;
	return online_iterate (prf, &dta, NULL);
}


/* Perform a strncat() operation with backslash escapes:
 *  - dst is the destintion buffer, already holding a NUL-terminated string
 *  - dstlen is the destination buffer size, with room for a trailing NUL
 *  - src is the source string to copy, ending with a NUL character
 *  - srcend is a character terminating src (on top of NUL, if it differs)
 *  - escme is a NUL-terminated character string with characters to escape
 * Escaping is done as with the printf() format string "\\%02x".
 * The return value is the number of characters added; this may be more than
 * the dstlen, but then the copy hasn't been executed.
 */
int strncatesc (char *dst, int dstlen, char *src, char srcend, char *escme) {
	int retval = 0;
	int esc;
	char *stacked = NULL;
	while ((*dst) && (dstlen > 0)) {
		dst++;
		dstlen--;
	}
	while (src) {
		// When done with src, pop stacked and retest
		if ((*src == '\0') || (*src == srcend)) {
			src = stacked;
			stacked = NULL;
			continue;
		}
		// Choose between escaped and unescaped copy
		esc = strchr (escme, *src) != NULL;
		retval += esc ? 3 : 1;
		if (retval <= dstlen) {
			if (esc) {
				sprintf (dst, "\\02x", *src++);
				dst += 3;
			} else {
				*dst++ = *src++;
			}
		}
	}
	retval++;
	if (retval <= dstlen) {
		*dst++ = '\0';
	}
	return retval;
}


/********** PROFILE-SPECIFIC ROUTINES **********/


/* As an example of what can be done with the routines below:
 *  - one route looks up an SRV record, and continues looking up each' IP info
 *  - an alternative route looks up AAAA then A, but continues as for SRV
 *  - regardless of these routes, open LDAP and STARTTLS, recording the cert
 *  - look into DANE for the LDAP server to check the cert, use dc=,dc= baseDN
 *  - change to another DN reference in LDAP if present; otherwise skip
 *  - look for (uid=) and (objectClass=pkiUser) with possibly extra attributes
 *  - match a given value against an attribute in either of the objects found
 *  - report success if either matches
 *
 * Such recipes are described as a nested/alternative composition of iterators
 * based on the elementary routines below.  Routines are _first/_next/_clean
 * for iteration, and _eval to evaluate a terminal condition for a node.
 */


//TODO: Look into OCSP (for X.509 certificate data, parsed out with Quick DER)
//TODO: Look into LDAP (for redirection of root)


/* Look into DNS or DNSSEC for AAAA and A records:
 *  - require DNSSEC if param starts with '!' (and then skip that character)
 *  - use the SRV servername if param is then 'S', or rid's domain for 'D'
 *  - lookup this name's AAAA records, and iterate over them, then
 *  - lookup this name's A    records, and iterate over them
 */
static void dns_ip_clean (crsval_t crs, online_data_t dta, val_t hdl) {
	// Be careful, dta->dnsip may be set to NULL switching from AAAA to A
	if (dta->dnsip) {
		ub_resolve_free (dta->dnsip);
		dta->dnsip = NULL;
	}
}
static int dns_ip_next (crsval_t crs, online_data_t dta, val_t hdl) {
	uint8_t *data;
	int ubrv;
	// Load the next element and take action if it is non-existent
	if ((!dta->dnsip->havedata) || dta->dnsip->data [dta->dnsip_next]) {
		if (dta->dnsip->qtype != LDNS_RR_TYPE_AAAA) {
			// Not the initial IPv6 (so IPv4) is through, so end
			return ONLINE_NOTFOUND;
		}
		// After we're through with AAAA, there's always A to try
		ub_resolve_free (dta->dnsip);
		dta->dnsip = NULL;
		ubrv = ub_resolve (ubctx, dta->dnsip_name, LDNS_RR_TYPE_A, LDNS_RR_CLASS_IN, &dta->dnsip);
		if (ubrv != 0) {
			tlog (TLOG_DAEMON, LOG_INFO, "DNS A query failed: ",
					ub_strerror (ubrv));
			return ONLINE_NOTFOUND;
		}
		if (!dta->dnsip->havedata) {
			return ONLINE_NOTFOUND;
		}
		dta->dnsip_next = 0;
	}
	// Check the sanity of the response
	if (dta->dnsip->bogus) {
printf ("DNS IP is BOGUS\n");
		return ONLINE_INVALID;		// DNS found a security problem
	}
	if (dta->dnsip_mustsecure) {
		if (!dta->dnsip->secure) {
			return ONLINE_NOTFOUND;	// Not a security problem
		}
	}
	if (dta->dnsip->data [dta->dnsip_next] == NULL) {
		return ONLINE_NOTFOUND;
	}
	switch (dta->dnsip->qtype) {
	case LDNS_RR_TYPE_A:
		if (dta->dnsip->len [dta->dnsip_next] != 4) {
printf ("DNS IP length is not 4\n");
			return ONLINE_INVALID;
		}
		dta->dnsip_addrfam = AF_INET;
		break;
	case LDNS_RR_TYPE_AAAA:
		if (dta->dnsip->len [dta->dnsip_next] != 16) {
printf ("DNS IP length is not 16\n");
			return ONLINE_INVALID;
		}
		dta->dnsip_addrfam = AF_INET6;
		break;
	default:
printf ("DNS IP query type is neither A nor AAAA\n");
		return ONLINE_INVALID;
	}
	// Deliver the response (dta->dnsip_addrfam has already been set)
	dta->dnsip_addr = dta->dnsip->data [dta->dnsip_next++];
	return ONLINE_SUCCESS;
}
static int dns_ip_first (crsval_t crs, online_data_t dta, val_t hdl, char *param) {
	int ubrv;
	dta->dnsip = NULL;
	dta->dnsip_mustsecure = 0;
	// Process the parameter: !S, !D, S, D
	if (*param == '!') {
		dta->dnsip_mustsecure = 1;
		param++;
	}
	switch (*param) {
	case 'S':
		assert (dta->srv_server != NULL);
		dta->dnsip_name = dta->srv_server;
		break;
	case 'D':
		dta->dnsip_name = strrchr (dta->rid, '@');
		dta->srv_port = 0;  // Signal clearly not using SRV records
		if (dta->dnsip_name != NULL) {
			dta->dnsip_name++;
		} else {
			dta->dnsip_name = dta->rid;
		}
		break;
	default:
printf ("DNS IP param is neither 'S' nor 'D'\n");
		return ONLINE_INVALID;
	}
	// Retrieve the AAAA field (passes through to _next if no AAAA found)
	ubrv = ub_resolve (ubctx, dta->dnsip_name, LDNS_RR_TYPE_AAAA, LDNS_RR_CLASS_IN, &dta->dnsip);
	if (ubrv != 0) {
		tlog (TLOG_DAEMON, LOG_INFO, "DNS AAAA query failed: ",
				ub_strerror (ubrv));
		return ONLINE_NOTFOUND;
	}
	// Actually return the next entry by setting fields in dta
	return dns_ip_next (crs, dta, hdl);
}


/* Look into DNS or DNSSEC for an SRV record:
 *  - require DNSSEC if param starts with '!' (and then skip that character)
 *  - use the domain part from rid
 *  - prefix with the _service._proto from the param
 *  - lookup SRV records
 *  - TODO: sort SRV records, or have a suitable iteration cursor
 *  - iterate over SRV records with first,next*,clean
 */
static void dns_srv_clean (crsval_t crs, online_data_t dta, val_t hdl) {
	if (dta->dnssrv != NULL) {
		ub_resolve_free (dta->dnssrv);
		dta->dnssrv = NULL;
	}
	if (dta->srv_server != NULL) {
		free (dta->srv_server);
		dta->srv_server = NULL;
	}
	dta->srv_port = 0;
}
static int dns_srv_next (crsval_t crs, online_data_t dta, val_t hdl) {
	int retval;
	uint8_t *data;
	int len;
	ldns_rdf *server_rdf;
	// Load the next element and return if it is non-existent
	data = dta->dnssrv->data [dta->dnssrv_next];
	if (data == NULL) {
		return ONLINE_NOTFOUND;
	}
	len  = dta->dnssrv->len  [dta->dnssrv_next];
	dta->dnssrv_next++;
	// Check the data element length
	if (len <= 2+2+2+1) {
		// hostname "." means the service is not available
		// TODO: Does hostname "." indeed map to 1 byte (length 0x00)?
printf ("DNS SRV next is short, %d\n", len);
		return (len < 2+2+2+1)? ONLINE_INVALID: ONLINE_NOTFOUND;
	}
	// Harvest information from the data element
	dta->srv_port = htons (*(uint16_t *) (data + 4));
	server_rdf = ldns_dname_new_frm_data (len - 6, data + 6);
	dta->srv_server = ldns_rdf2str (server_rdf);  // Freed in _cleanup
	ldns_rdf_free (server_rdf);
	// When we make it here, we can return success
	return ONLINE_SUCCESS;
}
static int dns_srv_first (crsval_t crs, online_data_t dta, val_t hdl, char *param) {
	int retval;
	int must_dnssec;
	int ubrv;
	char srvname [260];
	char *riddom;
	// Initialise for proper cleanup later
	dta->dnssrv = NULL;
	dta->srv_server = NULL;
	// Check DNSSEC requirement in param, leave _service._protocol
	if (*param == '!') {
		must_dnssec = 1;
		param++;
	} else {
		must_dnssec = 0;
	}
	dta->srv_prefix = param;
	// Find the domain in rid
	riddom = strrchr (dta->rid, '@');
	if (riddom != NULL) {
		riddom++;
	} else {
		riddom = dta->rid;
	}
	// Construct SRV name
	strncpy (srvname, param,  sizeof(srvname)-1);
	strncat (srvname, ".",    sizeof(srvname)-1);
	strncat (srvname, riddom, sizeof(srvname)-1);
	// Query Unbound and process the response
	ubrv = ub_resolve (ubctx, srvname, LDNS_RR_TYPE_SRV, LDNS_RR_CLASS_IN, &dta->dnssrv); // SRV,IN
	if (ubrv != 0) {
		tlog (TLOG_DAEMON, LOG_INFO, "DNS SRV query failed: ",
				ub_strerror (ubrv));
		return ONLINE_NOTFOUND;
	}
	if (!dta->dnssrv->havedata) {
		retval = ONLINE_NOTFOUND;
	} else if (dta->dnssrv->bogus) {
printf ("DNS SRV is BOGUS\n");
		retval = ONLINE_INVALID;	// Signal a security problem
	} else if (must_dnssec && !dta->dnssrv->secure) {
		retval = ONLINE_NOTFOUND;	// Not a security problem
	} else {
		retval = ONLINE_SUCCESS;
	}
	// Finish up in case of error before returning
	if (retval == ONLINE_SUCCESS) {
		dta->dnssrv_next = 0;
		retval = dns_srv_next (crs, dta, hdl);
	}
	return retval;
}


/* Look into DNSSEC for a TLSA record.  There are various ways of feeding
 * a servername and port, the last one prevails, but it is the programmer's
 * responsibility to always set both values.  When using SRV data, the
 * programmer must be certain that this source of data is secure.
 *
 * Briefly,
 *  - always require DNSSEC
 *  - use the domain part from rid
 *  - prefix with the _proto from srv_prefix (which is _service._proto)
 *  - prefix with the _port  from srv_port (except for client mode DANE)
 *  - lookup TLSA records, to store in dnstlsa
 *  - iterate over TLSA records with first,next*,clean
 *
 * The following flags may be set in param:
 *  - C to select client mode DANE, see draft-huque-dane-client-cert
 *  - c is like C but only if rid has a user part detected by '@' presence
 *  - S selects server, proto, port from DNS SRV (be sure the data is secure!)
 *  - D selects the server from rid
 *  - I selects the server from prior DNS IP queried hostname
 *  - Pnnn overrides the port number with the following digits
 *  - pnnn is like Pnnn but only if the port number has not been set yet
 *  - Tx sets the transport to x, t=>TCP, u=>UDP, s=>SCTP
 *  - tx is like Tx but only if the protocol has not been set yet
 */
static void dns_tlsa_clean (crsval_t crs, online_data_t dta, val_t hdl) {
	if (dta->dnstlsa != NULL) {
		ub_resolve_free (dta->dnstlsa);
		dta->dnstlsa = NULL;
	}
}
static int dns_tlsa_next (crsval_t crs, online_data_t dta, val_t hdl) {
	int retval;
	uint8_t *data;
	int len;
	// Load the next element and return if it is non-existent
	data = dta->dnstlsa->data [dta->dnstlsa_next];
	if (data == NULL) {
		return ONLINE_NOTFOUND;
	}
	len  = dta->dnstlsa->len  [dta->dnstlsa_next];
	dta->dnstlsa_next++;
	// Check the data element length
	if (len <= 2+2+2+1) {
		// 3 fields of 2 bytes and minimally 1 byte certificate data
printf ("DNS TLSA length is short, %d\n", len);
		return (len < 2+2+2+1)? ONLINE_INVALID: ONLINE_NOTFOUND;
	}
	// Harvest information from the data element
	dta->dane_certusage = htons (* (uint16_t *) (data + 0));
	dta->dane_selector  = htons (* (uint16_t *) (data + 2));
	dta->dane_matchtype = htons (* (uint16_t *) (data + 4));
	dta->dane_certdata     = data + 6;
	dta->dane_certdata_len = len - 6;
	// When we make it here, we can return success
	return ONLINE_SUCCESS;
}
static int dns_tlsa_first (crsval_t crs, online_data_t dta, val_t hdl, char *param) {
	int retval;
	int ubrv;
	char tlsaname [260];
	char *server = NULL;
	char *proto = NULL;
	uint16_t port = 0;
	int climode = 0;
	// Process parameters
	while (*param) {
		switch (*param++) {
		case 't':
			// tx is like Tx unless a protocol has already been set
			if (proto != NULL) {
				param++;
				break;
			}
		case 'T':
			// Tx is transport x; t for TCP, u for UDP, s for SCTP
			switch (*param++) {
			case 'u':
				proto = "_udp";
				break;
			case 't':
				proto = "_tcp";
				break;
			case 's':
				proto = "_sctp";
				break;
			default:
				assert ("Invalid transport type" == NULL);
			}
			break;
		case 'c':
			// Client mode 'C' but only if rid has an @ symbol
			if (strchr (dta->rid, '@') == NULL) {
				break;
			}
			// ...or else, continue into 'C' processing...
		case 'C':
			// Client mode (no _port), exp draft-huque-dane-client-cert
			climode = 1;
			break;
		case 'S':
			// SRV server name and port
			server = dta->srv_server;
			proto = strrchr (dta->srv_prefix, '.');
			port = dta->srv_port;
			break;
		case 'D':
			// Use the rid domain name (and separately set default port)
			server = strrchr (dta->rid, '@');
			if (server != NULL) {
				server++;
			} else {
				server = dta->rid;
			}
			break;
		case 'I':
			// dns_ip hostname, may have been derived from SRV
			server = dta->dnsip_name;
			break;
		case 'p':
			// Default port
			if (port != 0) {
				break;
			}
			// ...or else, continue into the explicit port code...
		case 'P':
			// Explicit port, overruling setup
			port = 0;
			while (('0' <= *param) && (*param <= '9')) {
				port *= 10;
				port += *param++ - '0';
			}
			break;
		}
	}
	// Assert assumptions that the foregoing code should have made true
	assert (port != 0);
	assert (server != NULL);
	// Initialise for proper cleanup later
	dta->dnstlsa = NULL;
	// Construct TLSA name, _port._proto.server (or _proto.server)
	assert (proto != NULL);
	proto++;
	assert (*proto != '\0');
	if (climode) {
		snprintf (tlsaname, sizeof(tlsaname)-2, "%s.%s",
			// draft-huque-dane-client-cert drops "_port."
			proto,
			server
			);
	} else {
		snprintf (tlsaname, sizeof(tlsaname)-2, "_%d.%s.%s",
			dta->srv_port,
			proto,
			server
			);
	}
	if (strlen (tlsaname) >= sizeof(tlsaname)-1) {
		// Too long, return as a failed lookup
		return ONLINE_NOTFOUND;
	}
	// Query Unbound and process the response
	ubrv = ub_resolve (ubctx, tlsaname, LDNS_RR_TYPE_TLSA, LDNS_RR_CLASS_IN, &dta->dnstlsa); // TLSA,IN
	if (ubrv != 0) {
		tlog (TLOG_DAEMON, LOG_INFO, "DNS TLSA query failed: ",
				ub_strerror (ubrv));
		return ONLINE_NOTFOUND;
	}
	if (!dta->dnstlsa->havedata) {
		retval = ONLINE_NOTFOUND;
	} else if (dta->dnstlsa->bogus) {
printf ("DNS TLSA is BOGUS\n");
		retval = ONLINE_INVALID;	// Signal a security problem
	} else if (!dta->dnstlsa->secure) {
		retval = ONLINE_NOTFOUND;	// Not a security problem
	} else {
		retval = ONLINE_SUCCESS;
	}
	// Finish up in case of error before returning
	if (retval == ONLINE_SUCCESS) {
		dta->dnstlsa_next = 0;
		retval = dns_tlsa_next (crs, dta, hdl);
	}
	return retval;
}


/* Connect to an LDAP server and start TLS.  Record certificate for DANE.
 *  - Use dnsip_addr / _addrfam as a pointer to the remote server
 *  - Use TCP with the srv_port (replaced with 389 if 0)
 *  - When SRV is bypassed, srv_port will be 0 (and thus result in port 389)
 *
 * Note that, although setup as an iterator, this is only to support child
 * operations based on it; there will never be a success from _next, all the
 * magic sits in _first and _cleanup.
 */
static void ldap_connect_clean (crsval_t crs, online_data_t dta, val_t hdl) {
	if (dta->ldap != NULL) {
		ldap_unbind (dta->ldap);
		dta->ldap = NULL;
	}
}
static int ldap_connect_next (crsval_t crs, online_data_t dta, val_t hdl) {
	// There is not actually anything to iterate over... so say "ni!"
	return ONLINE_NOTFOUND;
}
static int ldap_connect_first (crsval_t crs, online_data_t dta, val_t hdl, char *param) {
	// Connect to the LDAP server, either by srv_server or rid
	if (dta->srv_port != 0) {
		dta->ldap = ldap_open (dta->srv_server, dta->srv_port);
	} else {
		// Find the domain in rid
		char *riddom = strrchr (dta->rid, '@');
		if (riddom != NULL) {
			riddom++;
		} else {
			riddom = dta->rid;
		}
		dta->ldap = ldap_open (riddom, LDAP_PORT);
	}
	if (dta->ldap == NULL) {
		// Won't be freed in _cleanup due to the NULL value
		return ONLINE_NOTFOUND;
	}
	// Now perform a START TLS operation, assuming it is supported
	//TODO// ldap_start_tls_s (...) --> like to do it through the TLS Pool
	//TODO// Possible: RFC 4511, sections 4.12 + 4.14
	//TODO// ldap_extended_operation(), starrtls_minimal(), ldap_init_fd()
	// Use an Anonymous Simple Bind [Section 5.1.1 of RFC 4513]
#if 0
// A client that sends a LDAP request without doing a "bind" is treated
// as an anonymous client.
// Source: http://tldp.org/HOWTO/LDAP-HOWTO/authentication.html
	if (ldap_simple_bind_s (dta->ldap, "", "")) {
		// Rely on _cleanup to unbind/close dta->ldap
		return ONLINE_NOTFOUND;
	}
#endif
	return ONLINE_SUCCESS;
}


/* Search an LDAP hierarchy for an attributetype.  The baseDN for the
 * search is dc=,dc= based on the rid, and a filter constraint (uid=)
 * will be added if the rid has a username part.  In addition, an
 * objectClass pkiUser [RFC 4523] is required, and param is processed as
 * a series op options, ending in the attribute name A which is followed
 * by the NUL-terminated attribute type to retrieve.
 *
 * TODO: Instead of pkiUser, which is for X.509 only, we might use another.
 *
 * The param options are:
 *  - u requires absense  of the userid part in the rid
 *  - U requires presence of the userid part in the rid
 *  - c (TODO) might be used to require absense  of an objectClass (filtexpr?)
 *  - C (TODO) might be used to require presence of an objectClass
 *  - A terminates param; it is followed by the attribute type to request
 *	When ':' occurs before the attribute type, it is preceded by an
 *	objectClass to require; multiple such occurrences are alternatives.
 * An example param string would be "UApkiUser=userCertificate".
 *
 * A highly probable test for each of the elements found is comparison
 * with the data/len values passed from the calling environment; this may
 * be used, for instance, to match a certificate's binary value.
 */
static void ldap_getattr_clean (crsval_t crs, online_data_t dta, val_t hdl) {
	if (dta->ldap_attr) {
		// Freeing _attr is part of freeing the surrounding _attr_search
		dta->ldap_attr = NULL;
	}
	if (dta->ldap_attr_search) {
		ldap_msgfree (dta->ldap_attr_search);
		dta->ldap_attr_search = NULL;
	}
}
static int ldap_getattr_next (crsval_t crs, online_data_t dta, val_t hdl) {
	// Freeing old _attr is part of freeing the surrounding _attr_search
	if (dta->ldap_attr != NULL) {
		dta->ldap_attr = ldap_next_entry (dta->ldap, dta->ldap_attr);
	}
	return (dta->ldap_attr != NULL) ? ONLINE_SUCCESS : ONLINE_NOTFOUND;
}
static int ldap_getattr_first (crsval_t crs, online_data_t dta, val_t hdl, char *param) {
	int lrv;
	char base [260];
	int baselen = 0;
	char filter [260];
	char *attr [2];
	char *riddom = strrchr (dta->rid, '@');
	int got_user = (riddom != NULL);
	char *nextparam;
	if (got_user) {
		riddom++;
	} else {
		riddom = dta->rid;
	}
	// Initialise LDAP attributes for ldap_getattr_
	assert (dta->ldap != NULL);
	dta->ldap_attr_search = dta->ldap_attr = NULL;
	// Construct the search base
	base [0] = '\0';
	while (*riddom) {
		if (strlen (base) > sizeof(base)-6) {
			// Out of range, report as a failure
			return ONLINE_NOTFOUND;
		}
		strncat (base, (*base == '\0')? "dc=": ",dc=", sizeof(base)-1);
		// RFC 4514 escaping
		baselen += strncatesc (base, sizeof(base)-1, riddom, '.', "\\+,\"<=># ;");
		if (strlen (base) > sizeof(base)-2) {
			// Out of range, report as failure
			return ONLINE_NOTFOUND;
		}
		while ((*riddom) && (*riddom != '.')) {
			riddom++;
		}
		if (*riddom == '.') {
			riddom++;
		}
	}
	// Construct the search filter
	strncpy (filter, "(&", sizeof(filter)-1);
	if (got_user) {
		strncat (filter, "(uid=", sizeof(filter)-1);
		// RFC 4515 escaping
		strncatesc (filter, sizeof(filter)-1, dta->rid, '@', "*()\\");
		strncat (filter, ")",      sizeof(filter)-1);
	}
	strncat (filter, "(|", sizeof(filter)-1);
	// Parse and process arguments
	while (param) {
		switch (*param++) {
		case 'u':
			// Require absense of a userID in rid
			if (got_user) {
				return ONLINE_NOTFOUND;
			}
			break;
		case 'U':
			// Require having a userID in rid
			if (!got_user) {
				return ONLINE_NOTFOUND;
			}
			break;
		case 'A':
			// Setup attrs to return with one attribute type
			while (strchr (param, ':') != NULL) {
				strncat (filter, "(objectClass=", sizeof(filter)-1);
				// Return value counts '\0'
				param += strncatesc (filter, sizeof(filter)-1, param, ':', "*()\\");
				strncat (filter, ")", sizeof(filter)-1);
			}
			attr [0] = param;
			attr [1] = NULL;
			param = NULL;	// Terminate parsing param
			break;
		}
	}
	// Terminate the search string
	if (strlen (filter) > sizeof(filter)-2) {
		// Out of range, sadly report failure
		return ONLINE_NOTFOUND;
	}
	strncat (filter, "))", sizeof(filter)-1);
	// Submit the LDAP query
	lrv = ldap_search_st (dta->ldap,
				base, LDAP_SCOPE_SUBTREE, filter, attr, 0,
				&ldap_timeout, &dta->ldap_attr_search);
	if (lrv != 0) {
		if ((lrv != LDAP_NO_SUCH_OBJECT) && (lrv != LDAP_NO_SUCH_ATTRIBUTE)) {
			// Special case worthy of a notice in the system log
			tlog (TLOG_DAEMON, LOG_NOTICE,
				"Failed to find LDAP attribute %s under %s: %s",
				attr [0], base,
				ldap_err2string (lrv));
		}
		return ONLINE_NOTFOUND;
	}
	dta->ldap_attr = ldap_first_entry (dta->ldap, dta->ldap_attr_search);
	return (dta->ldap_attr != NULL) ? ONLINE_SUCCESS : ONLINE_NOTFOUND;
}


/* Test the value of the retrieved attribute against data/len.
 * The method used is simply an exact match with at least one of the entries
 * for the iterated attribute.
 */
static int ldap_attrcmp_eval (online_data_t dta, val_t hdl, char *param) {
	assert (dta->ldap != NULL);
	assert (dta->ldap_attr != NULL);
	void *cursor;
	char *atnm;
	struct berval **atvs;
	int i;
	int match = 0;
	// Fetch the each type into a cursor, then iterate over its values
	//TODO// This follows RFC 1823, yet there is a type error on cursor?!?
	for (atnm = ldap_first_attribute (dta->ldap, dta->ldap_attr, &cursor);
		atnm != NULL;
		atnm = ldap_next_attribute (dta->ldap, dta->ldap_attr, cursor)) {
		atvs = ldap_get_values_len (dta->ldap, dta->ldap_attr, atnm);
		for (i=0; atvs [i] != NULL; i++) {
			if ((atvs [i]->bv_len == dta->len) && (0 == memcmp (atvs [i]->bv_val, dta->data, dta->len))) {
				// Yippy, we found a matching attribute!
				match = 1;
			}
		}
		ldap_value_free_len (atvs);
	}
printf ("LDAP attribute comparison match is %d\n", match);
	return match ? ONLINE_SUCCESS : ONLINE_INVALID;
}


/* Test the value of a retrieved DANE record against data/len, which is
 * considered to be a concatenation of X.509 certificates in DER form.
 * Note that the concatenation is not an ASN.1 SEQUENCE but quite simply
 * a concatenation of the individual certificates.
 *
 * The method used for comparison is simply an exact match with at least
 * one of the entries for the iterated attribute.
 *
 * The following configuration parameters exist (and are necessary):
 *  - Unn (additionally) permits usage value nn
 *  - Snn (additionally) permits selector value nn
 *  - Mnn (additionally) permits matching value nn
 *
 * The code below is a full implementation of RFC 6698 for "DANE".
 */
static int dane_attrcmp_eval (online_data_t dta, val_t hdl, char *param) {
	assert (dta->dane_certdata != NULL);
	assert (dta->dane_certdata_len > 0);
	int certusage = -1;
	int selector = -1;
	int matchtype = -1;
	char type;
	int value;
	int *todo_value;
	uint16_t *dane_value;
	int match = 0;
	int cert_first, cert_last, i;
	gnutls_digest_algorithm_t hashtp;
	// Iterate over options, comparing each against the DANE-supplied value
	while (*param) {
		type = *param++;
		switch (type) {
		case 'U':
			todo_value = &certusage;
			dane_value = &dta->dane_certusage;
			break;
		case 'S':
			todo_value = &selector;
			dane_value = &dta->dane_selector;
			break;
		case 'M':
			todo_value = &matchtype;
			dane_value = &dta->dane_matchtype;
			break;
		default:
			assert ((type == 'U') || (type == 'S') || (type == 'M'));
		}
		value = 0;
		while (('0' <= *param) && (*param <= '9')) {
			value *= 10;
			value += *param++ - '0';
		}
		if (*dane_value == value) {
			*todo_value = value;
		}
	}
	// For success, require that one of each of the settings was matched
	if ((certusage == -1) || (selector == -1) || (matchtype == -1)) {
		return ONLINE_NOTFOUND;
	}
	// Process certusage:
	//  - 0 selects all but the first certificate as matching candidates
	//  - 1 selects only the first certificate
	//  - 2 selects only the last certificate
	//  - 3 selects only the first certificate, if its chain validates
	// We do not handle the "if" part of certusage 3 here; for that, we
	// have local policies telling us how to observe domains.  There is
	// a possibility to have such policies depend on information in DANE.
	int use_low = 0, use_mid = 0, use_top = 0;
	switch (certusage) {
	case 0:
		use_low = 1;
		break;
	case 1:
	case 3:
		use_low = 1;
		use_mid = 1;
		use_top = 1;
		break;
	case 2:
		use_top = 1;
		break;
	default:
		return ONLINE_NOTFOUND;
	}
	//TODO// chain validation for case 3?  But we prefer LOCAL policy :)
	cert_first = cert_last  = 0;
	// Process selector:
	//  - 0 selects the full certificate
	//  - 1 selects the SubjectPublicKeyInfo
	if ((selector != 0) && (selector != 1)) {
		return ONLINE_NOTFOUND;
	}
	// Process matchtype:
	//  - 0 compares the certificate as a binary value
	//  - 1 compares the certificate's SHA-256
	//  - 2 compares the certificate's SHA-512
	switch (matchtype) {
	case 0:
		hashtp = GNUTLS_DIG_NULL;
		break;
	case 1:
		hashtp = GNUTLS_DIG_SHA256;
		break;
	case 2:
		hashtp = GNUTLS_DIG_SHA512;
		break;
	default:
		return ONLINE_NOTFOUND;
	}
	// Now iterate over the certificates in the list, and compare to DANE
	dercursor certs, cert, next;
	certs.derptr = dta->data;
	certs.derlen = dta->len;
	int first = 1, last;
	if (der_iterate_first (&certs, &cert)) do {
		next = cert;
		last = !der_iterate_next (&next);
		// Decide whether to process this certificate
		if (use_low && first) {
			; // Approve
		} else if (use_top && last && !first) {
			; // Approve
		} else if (!use_mid) {
			continue; // Disapprove, iterate to next cert
		}
		// End of loop setup, now process
		uint8_t der_tag;
		uint8_t der_hlen;
		size_t der_ilen;
		if (selector == 1) {
			if (der_walk (&cert, to_subjectpublickeyinfo)) {
				continue;  // Failed
			}
		}
		if (der_header (&cert, &der_tag, &der_ilen, &der_hlen)) {
			continue;  // Failed
		}
		cert.derlen = der_hlen + der_ilen;
		// Apply hash function, if any
		uint8_t hashbuf [512 / 8];
		if (hashtp != GNUTLS_DIG_NULL) {
			assert (gnutls_hash_get_len (hashtp) <= sizeof (hashbuf));
			gnutls_hash_fast (hashtp, cert.derptr, cert.derlen, hashbuf);
			cert.derptr = hashbuf;
			cert.derlen = gnutls_hash_get_len (hashtp);
		}
		if ((cert.derlen == dta->dane_certdata_len) && (0 == memcmp (cert.derptr, dta->dane_certdata, cert.derlen))) {
			match = 1;
		}
		// Continue looping
	} while (first = 0, cert = next, !last);  // Yes, assignments in ()
	// Return the evaluation result
printf ("DANE attribute match is %d\n", match);
	return match ? ONLINE_SUCCESS : ONLINE_INVALID;
}


/********** PROFILE DEFINITION STRUCTURES **********/

//TODO: online_profile_t online_globaldir_x509_profile = { ... };
//TODO: online_profile_t online_dane_x509_profile = { ... };

/* Rough idea, GlobalDir lookup for user@domain.name under X.509 credentials:
    - map rid to domain name; lookup SRV with parameter "_ldap._tcp"
    - connect to LDAP server
    - map SRV info name to DANE; lookup TLSA
    - lookup TLSA for LDAP and check
    - search for user as specified by rid, (uid=) under dc=,dc=
    - compare attribute as provided by caller
   Note that looking back is required:
    - rid,data/len are now passed on, perhaps setup in structure?
    - SRV coordinates should be passed to connection and to DANE
    - TLS coordinates should be passed to TLSA check
   To enable both srv2dane strategies, make them altstrat w/ shared child
 */

static struct online_profile _gdir_x509_compare = {
	.eval = ldap_attrcmp_eval,
};

static struct online_profile _gdir_x509_attrs = {
	// NOT SO: .eval  = dane_attrcmp_eval,
	// TODO -- Compare DANE against X.509 information picked up
	.first = ldap_getattr_first,
	.next  = ldap_getattr_next,
	.clean = ldap_getattr_clean,
	.param = "UApkiUser:userCertificate",
	.child = &_gdir_x509_compare,
};

static struct online_profile _gdir_x509_tlsa = {
	.first = dns_tlsa_first,
	.next  = dns_tlsa_next,
	.clean = dns_tlsa_clean,
	.param = "SD",
	.child = &_gdir_x509_attrs,
};

static struct online_profile _gdir_x509_connect = {
	.first = ldap_connect_first,	// TODO: Pickup X.509 information
	.next  = ldap_connect_next,
	.clean = ldap_connect_clean,
	.param = "",
	.child = &_gdir_x509_tlsa,
};

static struct online_profile _gdir_x509_ip = {
	.first = dns_ip_first,
	.next  = dns_ip_next,
	.clean = dns_ip_clean,
	.param = "!S",
	.child = &_gdir_x509_connect,
};

static struct online_profile online_globaldir_x509_profile = {
	.first = dns_srv_first,
	.next  = dns_srv_next,
	.clean = dns_srv_clean,
	.param = "!_ldap._tcp",
	.child = &_gdir_x509_ip,
};

/* Check an X.509 end certificate or a concatenation of X.509 certificates
 * from end certificate to root certificate against the global directory.
 * Take care that the second use assumes mere binary concatenation, rather
 * than the ASN.1 type SEQUENCE OF Certificate.
 */
int online_globaldir_x509 (char *rid, uint8_t *data, uint16_t len) {
	if (strchr (rid, '@') == NULL) {
printf ("X.509 globaldir reference lacks '@'\n");
		return ONLINE_INVALID;
	}
	return online_run_profile (&online_globaldir_x509_profile, rid, data, len);
}

/* Check an X.509 certificate against DANE.  Provide with the domain.
 */
/* TODO
int online_dane_x509 (char *rid, uint8_t *data, uint16_t len) {
	if (strchr (rid, '@') != NULL) {
printf ("X.509 DANE reference lacks '@'\n");
		return ONLINE_INVALID;
	}
	return online_run_profile (&online_dane_x509_profile, rid, data, len);
}
*/



/********** MODULE MANAGEMENT ROUTINES **********/

void setup_online (void) {
	ubctx = ub_ctx_create ();
	if (ubctx == NULL) {
		tlog (TLOG_DAEMON, LOG_ERR, "Failed to setup DNS resolver context");
		exit (1);
	}
	// Perhaps add trust anchors with ub_ctx_add_ta()
	if (ub_ctx_add_ta_autr (ubctx,
			"/usr/local/etc/unbound/root.key" /* TODO:FIXED */)) {
		tlog (TLOG_DAEMON, LOG_ERR, "Failed to configure DNS root trust anchor in resolver context");
		exit (1);
	}
	// In an asynchronous program, this would thread { poll() + ub_poll() }
}

void cleanup_online (void) {
	// In an asynchronous program, stop the thread { poll() + ub_poll() }
	ub_ctx_delete (ubctx);
}

