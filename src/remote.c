/* tlspool/remote.c -- Contact remote information sources like DNS and LDAP */

#include "whoami.h"

#ifdef UNCONSIDERED_OLD_CODE_WITHOUT_DB_CONFIGURATION

#include <stdlib.h>
#include <string.h>

#include <errno.h>
#include <com_err.h>
#include <errortable.h>

#include <gnutls/gnutls.h>
#include <gnutls/abstract.h>

#include <tlspool/internal.h>

//NOTYET// #include <ldap.h>


#define LDAP_FILTER_TRUE	"(&)"
#define LDAP_FILTER_FALSE	"(|)"


/* Currently, we support a single LDAP proxy as our outward gateway for
 * LDAP queries.  When defined, it should resolve dc=,dc= DNs and pass
 * them on to an LDAP server found through a DNS SRV query.
 */
static LDAP *ldap_proxy;


/* Based on the domain name part of an identity, construct a dc=,dc=
 * distinguishedName that can be used as a baseDN.  When relying on a proxy
 * LDAP service, this is useful to locate and contact remote LDAP servers.
 */
static int domain2basedn (char *identity, char *basedn, size_t basednsz) {
	errno = ENOSYS;
	return -1;
}

/* Based on a domain name or a user@domain identity, construct a (uid=) or
 * tautology that can be used as a filter.
 */
static int identity2uidfilter (char *identity, char *atsign, char *filter, size_t filtersz) {
	errno = ENOSYS;
	return -1;
}


/* Fill the OpenPGP certificate data structure with a certificate found in
 * LDAP for the provided localid, which may be a domain name or user@domain.
 *
 * Searches are performed in two stages.  First, there is a query filtering
 * (uid=) under dc=,dc= and second, the search continues with OpenPGP-specific
 * patterns directly under the object(s) found.  When there is no user@ but
 * just a domain name, things are slightly different; in that case, the first
 * search is skipped, and the second phase looks for objects directly under
 * the current node.
 *
 * Return 0 on success or -1 on failure; on failure, set errno appropriately.
 */
int ldap_fetch_openpgp_cert (gnutls_openpgp_crt_t *pgpcrtdata, char *localid) {
	LDAP *server;
	char basedn [200];
	char filter [100];
	char *atpos = strrchr (localid, '@');
	//
	// Determine which LDAP server to use
	if (ldap_proxy) {
		server = ldap_proxy;
	} else {
		//TODO// Support local resolution of LDAP service?
		errno = ENOSYS;
		return -1;
	}
	//
	// Setup baseDN and filter for finding localid
	if (domain2basedn (atpos? atpos+1: localid, basedn, sizeof (basedn)) || identity2uidfilter (localid, atpos, filter, sizeof (filter))) {
		return -1;
	}
	if (!atpos) {
		strcpy (filter, LDAP_FILTER_TRUE);
	}
	//
	// Phase 1, only for user@domain identities: Find unique (uid=) object.
	if (atpos) {
		static char *attrs [2] = { LDAP_NO_ATTRS, NULL };
		static struct timeval timeout_10s = { .tv_sec = 10 };
		LDAPMessage *res;
		int lderr = LDAP_SUCCESS+1; //TODO// ldap_search_ext_s (server, basedn, LDAP_SCOPE_SUBTREE, filter, attrs, 0, NULL, NULL, &timeout_10s, 1, &res);
		if (lderr != LDAP_SUCCESS) {
			switch (lderr) {
			//TODO// Better translation of error conditions
			default:
				errno = EIO;
				break;
			}
			//TODO// Free LDAP structures, if any
			return -1;
		}
		//TODO// Fill the baseDN with the DN in the search result
		//TODO// Free LDAP structures, if any
	}
	//
	// Phase 2: Find OpenPGP objects, by looking at direct children.
	//	For user@domain, start from the baseDN changed in phase 1
	//	For domain name, start from the baseDN
}

#endif /* UNCONSIDERED_OLD_CODE_WITHOUT_DB_CONFIGURATION */
