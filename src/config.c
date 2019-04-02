/* tlspool/config.c -- Parse & Process the configuration file */

#include "whoami.h"

#include <stdlib.h>
#include <stdbool.h>
#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <limits.h>

#include <errno.h>
#include <com_err.h>
#include <errortable.h>

#ifndef WINDOWS_PORT
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/file.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <pwd.h>
#include <grp.h>
#include <unistd.h>
#endif /* WINDOWS_PORT */

#include <syslog.h>
#include <fcntl.h>
#include <signal.h>

//NOTYET// #include <ldap.h>

#ifdef HAVE_SYSTEMD
#  include <systemd/sd-daemon.h>
#endif

#include <tlspool/internal.h>

//NOTYET// #include <libmemcached/memcached.h>

//NOTYET// static LDAP *ldap_handle;

//NOTYET// static struct memcached_st *cache;

static int kill_old_pid = 0;

typedef void (*cfghandler) (char *item, int itemno, char *value);

struct cfgopt {
	char *cfg_name;
	cfghandler cfg_handler;
	int cfg_idx;
};

enum VARS {
	CFGVAR_DAEMON_PIDFILE,
	CFGVAR_SOCKET_USER,
	CFGVAR_SOCKET_GROUP,
	CFGVAR_SOCKET_MODE,
	CFGVAR_PKCS11_PATH,
	CFGVAR_PKCS11_PIN,
	CFGVAR_CACHE_TTL,
	CFGVAR_CACHE_PORT,
	CFGVAR_PRIVACY_ATTEMPT,
	CFGVAR_LDAP_PROXY,
	CFGVAR_RADIUS_AUTHN,
	CFGVAR_RADIUS_AUTHZ,
	CFGVAR_RADIUS_ACCT,
	CFGVAR_LOG_LEVEL,
	CFGVAR_LOG_FILTER,
	CFGVAR_LOG_STDERR,
	CFGVAR_DBENV_DIR,
	CFGVAR_DB_LOCALID,
	CFGVAR_DB_DISCLOSE,
	CFGVAR_DB_TRUST,
	CFGVAR_TLS_DHPARAMFILE,
	CFGVAR_TLS_MAXPREAUTH,
	CFGVAR_TLS_ONTHEFLY_SIGNCERT,
	CFGVAR_TLS_ONTHEFLY_SIGNKEY,
	CFGVAR_FACILITIES_DENY,
	CFGVAR_FACILITIES_ALLOW,
	CFGVAR_DNSSEC_ROOTKEY,
	CFGVAR_KRB_CLIENT_KEYTAB,
	CFGVAR_KRB_SERVER_KEYTAB,
	CFGVAR_KRB_CLIENT_CREDCACHE,
	CFGVAR_KRB_SERVER_CREDCACHE,
	CFGVAR_POSTQUANTUM_AUTH,
	CFGVAR_POSTQUANTUM_ENCRYPT,
	CFGVAR_POSTQUANTUM_HANDSHAKE,
	//
	CFGVAR_LENGTH,
	CFGVAR_NONE = -1
};

void cfg_setvar (char *item, int itemno, char *value);
void cfg_socketname (char *item, int itemno, char *value);
void cfg_p11path (char *item, int itemno, char *value);
void cfg_p11token (char *item, int itemno, char *value);
void cfg_ldap (char *item, int itemno, char *value);
void cfg_cachehost (char *item, int itemno, char *value);
#ifndef WINDOWS_PORT
void cfg_pidfile (char *item, int itemno, char *value);
void cfg_user (char *item, int itemno, char *value);
void cfg_group (char *item, int itemno, char *value);
void cfg_chroot (char *item, int itemno, char *value);
#endif

struct cfgopt config_options [] = {
	"socket_user",		cfg_setvar,	CFGVAR_SOCKET_USER,
	"socket_group",		cfg_setvar,	CFGVAR_SOCKET_GROUP,
	"socket_mode",		cfg_setvar,	CFGVAR_SOCKET_MODE,
	"socket_name",		cfg_socketname,	CFGVAR_NONE,
	"pkcs11_path",		cfg_setvar,	CFGVAR_PKCS11_PATH,
	"pkcs11_pin",		cfg_p11path,	CFGVAR_PKCS11_PIN,
	"pkcs11_token",		cfg_p11token,	CFGVAR_NONE,
	"ldap_proxy",		cfg_ldap,	CFGVAR_LDAP_PROXY,
	"memcache_ttl",		cfg_setvar,	CFGVAR_CACHE_TTL,
	"memcache_port",	cfg_setvar,	CFGVAR_CACHE_PORT,
	"memcache_host",	cfg_cachehost,	CFGVAR_NONE,
	"privacy_attempt",	cfg_setvar,	CFGVAR_PRIVACY_ATTEMPT,
	"radius_authn",		cfg_setvar,	CFGVAR_RADIUS_AUTHN,
	"radius_authz",		cfg_setvar,	CFGVAR_RADIUS_AUTHZ,
	"radius_acct",		cfg_setvar,	CFGVAR_RADIUS_ACCT,
	"log_level",		cfg_setvar,	CFGVAR_LOG_LEVEL,
	"log_filter",		cfg_setvar,	CFGVAR_LOG_FILTER,
	"log_stderr",		cfg_setvar,	CFGVAR_LOG_STDERR,
	"dbenv_dir",		cfg_setvar,	CFGVAR_DBENV_DIR,
	"db_localid",		cfg_setvar,	CFGVAR_DB_LOCALID,
	"db_disclose",		cfg_setvar,	CFGVAR_DB_DISCLOSE,
	"db_trust",		cfg_setvar,	CFGVAR_DB_TRUST,
	"tls_dhparamfile",	cfg_setvar,	CFGVAR_TLS_DHPARAMFILE,
	"tls_maxpreauth",	cfg_setvar,	CFGVAR_TLS_MAXPREAUTH,
	"tls_onthefly_signcert",cfg_setvar,	CFGVAR_TLS_ONTHEFLY_SIGNCERT,
	"tls_onthefly_signkey",	cfg_setvar,	CFGVAR_TLS_ONTHEFLY_SIGNKEY,
	"deny_facilities",	cfg_setvar,	CFGVAR_FACILITIES_DENY,
	"allow_facilities",	cfg_setvar,	CFGVAR_FACILITIES_ALLOW,
	"dnssec_rootkey",	cfg_setvar,	CFGVAR_DNSSEC_ROOTKEY,
	"kerberos_client_keytab",   cfg_setvar,	CFGVAR_KRB_CLIENT_KEYTAB,
	"kerberos_server_keytab",   cfg_setvar,	CFGVAR_KRB_SERVER_KEYTAB,
	"kerberos_client_credcache",cfg_setvar,	CFGVAR_KRB_CLIENT_CREDCACHE,
	"kerberos_server_credcache",cfg_setvar,	CFGVAR_KRB_SERVER_CREDCACHE,
	"quantum_proof_authentication",cfg_setvar, CFGVAR_POSTQUANTUM_AUTH,
	"quantum_proof_encryption",cfg_setvar,	CFGVAR_POSTQUANTUM_ENCRYPT,
	"quantum_proof_handshake",cfg_setvar,	CFGVAR_POSTQUANTUM_HANDSHAKE,
#ifndef WINDOWS_PORT
	"daemon_pidfile",	cfg_pidfile,	CFGVAR_DAEMON_PIDFILE,
	"daemon_user",		cfg_user,	CFGVAR_NONE,
	"daemon_group",		cfg_group,	CFGVAR_NONE,
	"daemon_chroot",	cfg_chroot,	CFGVAR_NONE,
#endif /* WINDOWS_PORT */
	NULL,			NULL,		CFGVAR_NONE
};

struct var2val {
	char *name;
	unsigned int optval;
};

struct var2val v2v_log_level [] = {
	{ "EMERG", LOG_EMERG },
	{ "EMERGENCY", LOG_EMERG },
	{ "ALERT", LOG_ALERT },
	{ "CRIT", LOG_CRIT },
	{ "CRITICAL", LOG_CRIT },
	{ "ERR", LOG_ERR },
	{ "ERROR", LOG_ERR },
	{ "WARNING", LOG_WARNING },
	{ "WARN", LOG_WARNING },
	{ "NOTICE", LOG_NOTICE },
	{ "NOTE", LOG_NOTICE },
	{ "INFO", LOG_INFO },
	{ "DEBUG", LOG_DEBUG },
	{ "*", LOG_DEBUG },
	{ NULL, 0 }
};

struct var2val v2v_log_filter [] = {
	{ "*", ~0 },
	{ "TLS", TLOG_TLS },
	{ "PKCS11", TLOG_PKCS11 },
	{ "DB", TLOG_DB },
	{ "FILES", TLOG_FILES },
	{ "CRYPTO", TLOG_CRYPTO },
	{ "CERT", TLOG_CERT },
	{ "USER", TLOG_USER },
	// AUTHN/AUTHZ/CREDS/SESSION are not yet generated
	{ "COPYCAT", TLOG_COPYCAT },
	{ "UNIXSOCK", TLOG_UNIXSOCK },
	{ "DAEMON", TLOG_DAEMON },
	{ NULL, 0 }
};

struct var2val v2v_log_perror [] = {
	{ "YES", LOG_PERROR },
	{ "1", LOG_PERROR },
	{ "*", LOG_PERROR },
	{ "NO", 0 },
	{ "0", 0 },
	{ NULL, 0 }
};

struct var2val v2v_facility_flag [] = {
	{ "starttls", PIOF_FACILITY_STARTTLS },
	{ "startgss", PIOF_FACILITY_STARTGSS },
	{ "startssh", PIOF_FACILITY_STARTSSH },
	{ "*",        PIOF_FACILITY_ALL_CURRENT },
	{ NULL, 0 }
};

static char *configvars [CFGVAR_LENGTH];

#ifdef WINDOWS_PORT
#include "config_windows.c"
#else
#include "config_posix.c"
#endif

static unsigned int parse_var2val (char *word, int wlen, struct var2val *patterns, unsigned int defaultvalue) {
	if (word == NULL) {
		return defaultvalue;
	}
	if (wlen < 0) {
		wlen = strlen (word);
	}
	while (patterns->name) {
		if (strlen (patterns->name) == wlen) {
			if (strncasecmp (patterns->name, word, wlen) == 0) {
				return patterns->optval;
			}
		}
		patterns++;
	}
	return defaultvalue;
}

static unsigned int parse_var2val_list (char *wordlist, struct var2val *patterns, unsigned int defaultvalue) {
	int comma;
	unsigned int retval = 0;
	if (wordlist == NULL) {
		return defaultvalue;
	}
	while (*wordlist) {
		comma = strcspn (wordlist, ",");
		retval |= parse_var2val (wordlist, comma, patterns, 0);
		wordlist += comma;
		if (*wordlist == ',') {
			wordlist++;
		}
	}
	return retval;
}


/* General configfile parser */

void parse_cfgfile (char *filename, int kill_competition) {
	FILE *cf = fopen (filename, "r");
	char line [514];
	int linelen;
	int eof = 0;
	char *here;
	struct cfgopt *curopt;
	int found;
	kill_old_pid = kill_competition;
	if (!cf) {
		perror ("Failed to open configuration file");
		exit (1);
	}
	while (!eof) {
		if (!fgets (line, sizeof (line)-1, cf)) {
			if (feof (cf)) {
				eof = 1;
				continue;
			} else {
				perror ("Error while reading configuration file");
				exit (1);
			}
		}
		linelen = strlen (line);
		if (linelen == 0) {
			eof = 1;
			continue;
		}
		if (line [linelen-1] == (char) EOF) {
			linelen--;
			eof = 1;
		}
		if (line [linelen-1] != '\n') {
			fprintf (stderr, "Configuration line too long\n");
			exit (1);
		}
		line [--linelen] = 0;
		if (linelen == 0) {
			continue;
		}
		if (line [0] == '#') {
			continue;
		}
		here = line;
		while ((*here) && isspace (*here)) {
			here++;
		}
		if (!*here) {
			continue;
		}
		if (here != line) {
			fprintf (stderr, "Configuration line starts with whitespace:\n%s\n", line);
			exit (1);
		}
		while ((*here) && (*here != ' ')) {
			here++;
		}
		if (!*here) {
			fprintf (stderr, "Configuration line misses space after keyword:\n%s\n", line);
			exit (1);
		}
		*here++ = 0;
		curopt = config_options;
		while (curopt->cfg_name) {
			if (strcmp (curopt->cfg_name, line) == 0) {
				break;
			} else {
				curopt++;
			}
		}
		if (!curopt->cfg_name) {
			fprintf (stderr, "Unknown configuration option %s\n", line);
			exit (1);
		}
		curopt->cfg_handler (line, curopt->cfg_idx, here);
	}
	fclose (cf);
}

void cfg_setvar (char *item, int itemno, char *value) {
	if (configvars [itemno]) {
		free (configvars [itemno]);
	}
	configvars [itemno] = strdup (value);
	if (!configvars [itemno]) {
		fprintf (stderr, "Out of memory duplicating configuration string\n");
		exit (1);
	}
#ifdef DEBUG
	fprintf (stdout, "DEBUG: SETUP   %s AS %s\n", item, value);
#endif
}

unsigned int cfg_log_perror (void) {
	return parse_var2val (configvars [CFGVAR_LOG_STDERR], -1, v2v_log_perror, 0);
}

unsigned int cfg_log_level (void) {
	return parse_var2val (configvars [CFGVAR_LOG_LEVEL], -1, v2v_log_level, LOG_ERR);
}

unsigned int cfg_log_filter (void) {
	return parse_var2val_list (configvars [CFGVAR_LOG_FILTER], v2v_log_filter, ~0);
}

static void free_p11pin (void) {
	char *pin = configvars [CFGVAR_PKCS11_PIN];
	if (pin) {
		memset (pin, 0, strlen (pin));
		free (pin);
		configvars [CFGVAR_PKCS11_PIN] = NULL;
	}
}

void cfg_p11path (char *item, int itemno, char *value) {
#ifdef DEBUG
	fprintf (stdout, "DEBUG: DECLARE %s AS %s\n", item, value);
#endif
	cfg_setvar (item, itemno, value);
	//TODO:WHY?// free_p11pin ();
}

void cfg_p11token (char *item, int itemno, char *value) {
	if (!configvars [CFGVAR_PKCS11_PATH]) {
		fprintf (stderr, "You must specify pkcs11_path before any number of pkcs11_token\n");
		exit (1);
	}
#ifndef CONFIG_PARSE_ONLY
	starttls_pkcs11_provider (configvars [CFGVAR_PKCS11_PATH]);
#endif
}


char *cfg_p11pin (void) {
	return configvars [CFGVAR_PKCS11_PIN];
}

void cfg_ldap (char *item, int itemno, char *value) {
	if (configvars [CFGVAR_LDAP_PROXY]) {
		fprintf (stderr, "This version ignores additional LDAP proxy servers\n");
	} else {
#ifndef CONFIG_PARSE_ONLY
		fprintf (stderr, "This version ignores all LDAP proxy servers\n");
		//NOTYET// ldap_handle = NULL;
		//NOTYET// if (ldap_initialize (&ldap_handle, value) || !ldap_handle) {
		//NOTYET// 	fprintf (stderr, "Failure to setup LDAP proxy server\n");
		//NOTYET// 	exit (1);
		//NOTYET// } else {
		//NOTYET// 	cfg_setvar (item, itemno, value);
		//NOTYET// }
#endif
	}
}

void cfg_cachehost (char *item, int itemno, char *value) {
	int port;
	int ttl;
	//NOTYET// if (cache == NULL) {
	//NOTYET// 	cache = memcached_create (NULL);
	//NOTYET// 	if (cache == NULL) {
	//NOTYET// 		fprintf (stderr, "Failed to create memcached administrative structures\n");
	//NOTYET// 		exit (1);
	//NOTYET// 	}
	//NOTYET// }
	//NOTYET// port = MEMCACHED_DEFAULT_PORT;
	if (configvars [CFGVAR_CACHE_PORT]) {
		port = atoi (configvars [CFGVAR_CACHE_PORT]);
	}
#ifndef CONFIG_PARSE_ONLY
	//NOTYET// if (memcached_server_add (cache, value, port)) {
		fprintf (stderr, "Failed to add memcached server %s:%d\n", value, port);
		exit (1);
	//NOTYET// }
#endif
}

char *cfg_dbenv_dir (void) {
	return configvars [CFGVAR_DBENV_DIR];
}

char *cfg_db_localid (void) {
	char *dbname = configvars [CFGVAR_DB_LOCALID];
	if (dbname == NULL) {
		dbname = "localid.db";
	}
	return dbname;
}

char *cfg_db_disclose (void) {
	char *dbname = configvars [CFGVAR_DB_DISCLOSE];
	if (dbname == NULL) {
		dbname = "disclose.db";
	}
	return dbname;
}

char *cfg_db_trust (void) {
	char *dbname = configvars [CFGVAR_DB_TRUST];
	if (dbname == NULL) {
		dbname = "trust.db";
	}
	return dbname;
}

char *cfg_tls_dhparamfile (void) {
	return configvars [CFGVAR_TLS_DHPARAMFILE];
}

unsigned int cfg_tls_maxpreauth (void) {
	char *mps = configvars [CFGVAR_TLS_MAXPREAUTH];
	unsigned long mpi = 32768;
	if (mps != NULL) {
		mpi = strtoul (mps, &mps, 10);
		if (mpi > UINT_MAX) {
			mpi = 32768;
		}
	}
	return (unsigned int) mpi;
}

char *cfg_tls_onthefly_signcert (void) {
	// Require a signing key to return the certificate
	if (configvars [CFGVAR_TLS_ONTHEFLY_SIGNKEY]) {
		return configvars [CFGVAR_TLS_ONTHEFLY_SIGNCERT];
	} else {
		return NULL;
	}
}

char *cfg_tls_onthefly_signkey (void) {
	// Require a certificate to return the signing key
	if (configvars [CFGVAR_TLS_ONTHEFLY_SIGNCERT]) {
		return configvars [CFGVAR_TLS_ONTHEFLY_SIGNKEY];
	} else {
		return NULL;
	}
}

uint32_t cfg_facilities (void) {
	uint32_t deny, allow;
	deny  = parse_var2val_list (
			configvars [CFGVAR_FACILITIES_DENY ],
			v2v_facility_flag,
			0);
	allow = parse_var2val_list (
			configvars [CFGVAR_FACILITIES_ALLOW],
			v2v_facility_flag,
			PIOF_FACILITY_ALL_CURRENT);
	return PIOF_FACILITY_ALL_CURRENT & allow & ~deny;
}

char *cfg_dnssec_rootkey (void) {
	// Require the root key filename for use with DNSSEC
	if (configvars [CFGVAR_DNSSEC_ROOTKEY]) {
		return configvars [CFGVAR_DNSSEC_ROOTKEY];
	} else {
		return "/etc/unbound/root.key";
	}
}

char *cfg_krb_client_keytab (void) {
	return configvars [CFGVAR_KRB_CLIENT_KEYTAB];
}

char *cfg_krb_server_keytab (void) {
	return configvars [CFGVAR_KRB_SERVER_KEYTAB];
}

char *cfg_krb_client_credcache (void) {
	return configvars [CFGVAR_KRB_CLIENT_CREDCACHE];
}

char *cfg_krb_server_credcache (void) {
	return configvars [CFGVAR_KRB_SERVER_CREDCACHE];
}

static char *nope [] = { "NO", "No", "no", "FALSE", "False", "false", "NOPE", "Nope", "nope", "NAY", "Nay", "nay", "0", NULL };
static char *yep [] = { "YES", "Yes", "yes", "TRUE", "True", "true", "YEP", "Yep", "yep", "AYE", "Aye", "aye", "1", NULL };

/* Tactical phase 1.  Default to no because we lack general algorithms */
bool cfg_postquantum_auth (void) {
	// Commemmorable selection:
	static char **jawohl = yep;
	if (configvars [CFGVAR_POSTQUANTUM_AUTH] != NULL) {
		while (*jawohl) {
			if (strstr (configvars [CFGVAR_POSTQUANTUM_AUTH], *jawohl)) {
				return true;
			}
			jawohl++;
		}
	}
	// No match; err on the forgiving side
	return false;
}

/* Tactical phase 1.  Default to no because we lack general algorithms */
bool cfg_postquantum_encrypt (void) {
	// Commemmorable selection:
	static char **jawohl = yep;
	if (configvars [CFGVAR_POSTQUANTUM_ENCRYPT] != NULL) {
		while (*jawohl) {
			if (strstr (configvars [CFGVAR_POSTQUANTUM_ENCRYPT], *jawohl)) {
				return true;
			}
			jawohl++;
		}
	}
	// No match; err on the forgiving side
	return false;
}

/* Tactical phase 1.  Default to no because we lack general algorithms */
bool cfg_postquantum_handshake (void) {
	// Commemmorable selection:
	static char **jawohl = yep;
	if (configvars [CFGVAR_POSTQUANTUM_HANDSHAKE] != NULL) {
		while (*jawohl) {
			if (strstr (configvars [CFGVAR_POSTQUANTUM_HANDSHAKE], *jawohl)) {
				return true;
			}
			jawohl++;
		}
	}
	// No match; err on the forgiving side
	return false;
}
