/* tlspool/config.c -- Parse & Process the configuration file */

#include <config.h>

#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <ctype.h>
#include <string.h>

#include <sys/socket.h>
#include <sys/types.h>
#include <sys/file.h>
#include <sys/un.h>

#include <syslog.h>
#include <fcntl.h>
#include <pwd.h>
#include <grp.h>
#include <signal.h>

#include <ldap.h>

#include <tlspool/internal.h>

#include <libmemcached/memcached.h>

static LDAP *ldap_handle;

static struct memcached_st *cache;

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
	CFGVAR_TLS_DHPARAMFILE,
	//
	CFGVAR_LENGTH,
	CFGVAR_NONE = -1
};

void cfg_setvar (char *item, int itemno, char *value);
void cfg_pidfile (char *item, int itemno, char *value);
void cfg_socketname (char *item, int itemno, char *value);
void cfg_user (char *item, int itemno, char *value);
void cfg_group (char *item, int itemno, char *value);
void cfg_chroot (char *item, int itemno, char *value);
void cfg_p11path (char *item, int itemno, char *value);
void cfg_p11token (char *item, int itemno, char *value);
void cfg_ldap (char *item, int itemno, char *value);
void cfg_cachehost (char *item, int itemno, char *value);

struct cfgopt config_options [] = {
	"daemon_pidfile",	cfg_pidfile,	CFGVAR_DAEMON_PIDFILE,
	"socket_user",		cfg_setvar,	CFGVAR_SOCKET_USER,
	"socket_group",		cfg_setvar,	CFGVAR_SOCKET_GROUP,
	"socket_mode",		cfg_setvar,	CFGVAR_SOCKET_MODE,
	"socket_name",		cfg_socketname,	CFGVAR_NONE,
	"daemon_user",		cfg_user,	CFGVAR_NONE,
	"daemon_group",		cfg_group,	CFGVAR_NONE,
	"daemon_chroot",	cfg_chroot,	CFGVAR_NONE,
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
	"tls_dhparamfile",	cfg_setvar,	CFGVAR_TLS_DHPARAMFILE,
	//
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
	if ((wordlist == NULL) || (*wordlist == '\0')) {
		return defaultvalue;
	}
	while (*wordlist) {
		comma = strcspn (wordlist, ",");
		retval |= parse_var2val (wordlist, comma, patterns, 0);
		wordlist += comma + 1;
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


static char *configvars [CFGVAR_LENGTH];

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

void unlink_pidfile (void) {
	unlink (configvars [CFGVAR_DAEMON_PIDFILE]);
}

void cfg_pidfile (char *item, int itemno, char *value) {
	static int fh = 0;
	if (fh) {
		fprintf (stderr, "You can specify only one PID file\n");
		exit (1);
	}
	cfg_setvar (item, CFGVAR_DAEMON_PIDFILE, value);
	atexit (unlink_pidfile);
	fh = open (value, O_RDWR | O_CREAT, 0664);
	char pidbuf [10];
	if (fh < 0) {
		perror ("Failed to open PID file");
		exit (1);
	}
retry:
	if (flock (fh, LOCK_EX | LOCK_NB) != 0) {
		if (errno == EWOULDBLOCK) {
			pid_t oldpid;
			bzero (pidbuf, sizeof (pidbuf));
			read (fh, pidbuf, sizeof (pidbuf)-1);
			oldpid = atoi (pidbuf);
			if (kill_old_pid) {
				if (kill (oldpid, SIGHUP) == 0) {
					fprintf (stderr, "Sent hangup to old daemon with PID %s\n", pidbuf);
					sleep (1);
				}
				lseek (fh, 0, SEEK_SET);
				errno = 0;
				goto retry;
			}
			if (kill (oldpid, 0) != -1) {
				fprintf (stderr, "Another daemon owns the PID file: process %s", pidbuf);
				exit (1);
			}
		} else {
			perror ("Failed to own the PID file");
			exit (1);
		}
	}
	snprintf (pidbuf, sizeof (pidbuf)-1, "%d\n", getpid ());
	if (write (fh, pidbuf, strlen (pidbuf)) != strlen (pidbuf)) {
		perror ("Failed to write all bytes to PID file");
		exit (1);
	}
	ftruncate (fh, strlen (pidbuf));
	fsync (fh);
	//
	// Note: The file remains open -- to sustain the flock on it
	//
}

void cfg_socketname (char *item, int itemno, char *value) {
	struct sockaddr_un sun;
	int sox;
	uid_t me = getuid ();
	gid_t my = getgid ();
	if (strlen (value) + 1 > sizeof (sun.sun_path)) {
		fprintf (stderr, "Socket path too long: %s\n", value);
		exit (1);
	}
	strcpy (sun.sun_path, value);
	sun.sun_family = AF_UNIX;
	if (configvars [CFGVAR_DAEMON_PIDFILE]) {
		//
		// Note: Only be so kind to unlink when PID file is owned
		//
		unlink (value);
	}
	sox = socket (AF_UNIX, SOCK_STREAM, 0);
	if (sox < 0) {
		perror ("Failed to open UNIX socket");
		exit (1);
	}
	if (bind (sox, (struct sockaddr *) &sun, SUN_LEN (&sun)) == -1) {
		perror ("Failed to bind to UNIX socket");
		exit (1);
	}
	if (listen (sox, 5) == -1) {
		perror ("Failed to listen to UNIX socket");
		exit (1);
	}
	//
	// Now continue to set uid, gid, mode for the socket
	//
	if (configvars [CFGVAR_SOCKET_USER]) {
		struct passwd *pwd = getpwnam (configvars [CFGVAR_SOCKET_USER]);
		if (!pwd) {
			fprintf (stderr, "Failed to find socket user %s\n", value);
			exit (1);
		}
		me = pwd->pw_uid;
	}
	if (configvars [CFGVAR_SOCKET_GROUP]) {
		struct group *grp = getgrnam (configvars [CFGVAR_SOCKET_GROUP]);
		if (!grp) {
			fprintf (stderr, "Failed to find socket group %s\n", value);
			exit (1);
		}
		my = grp->gr_gid;
	}
	if (chown (value, me, my) != 0) {
		perror ("Failed to change socket user/group");
		exit (1);
	}
	if (configvars [CFGVAR_SOCKET_MODE]) {
		int mode = strtoul (configvars [CFGVAR_SOCKET_MODE], NULL, 0);
		if (chmod (value, mode) != 0) {
			perror ("Failed to change socket mode");
			exit (1);
		}
	}
	register_server_socket (sox);
}

void cfg_user (char *item, int itemno, char *value) {
#ifdef DEBUG
	fprintf (stdout, "DEBUG: DECLARE %s AS %s\n", item, value);
#endif
	struct passwd *pwd = getpwnam (value);
	if (!pwd) {
		fprintf (stderr, "Failed to find username %s\n", value);
		exit (1);
	}
	setuid (pwd->pw_uid);
}

void cfg_group (char *item, int itemno, char *value) {
#ifdef DEBUG
	fprintf (stdout, "DEBUG: DECLARE %s AS %s\n", item, value);
#endif
	struct group *grp = getgrnam (value);
	if (!grp) {
		fprintf (stderr, "Failed to find group name %s\n", value);
		exit (1);
	}
	setgid (grp->gr_gid);
}

void cfg_chroot (char *item, int itemno, char *value) {
	if (chroot (value) != 0) {
		perror ("Failed to chroot");
		exit (1);
	}
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
		bzero (pin, strlen (pin));
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
	starttls_pkcs11_provider (configvars [CFGVAR_PKCS11_PATH]);
}


char *cfg_p11pin (void) {
	return configvars [CFGVAR_PKCS11_PIN];
}

void cfg_ldap (char *item, int itemno, char *value) {
	if (configvars [CFGVAR_LDAP_PROXY]) {
		fprintf (stderr, "This version ignores additional LDAP proxy servers\n");
	} else {
		fprintf (stderr, "This version ignores all LDAP proxy servers\n");
		//TODO// ldap_handle = NULL;
		//TODO// if (ldap_initialize (&ldap_handle, value) || !ldap_handle) {
		//TODO// 	fprintf (stderr, "Failure to setup LDAP proxy server\n");
		//TODO// 	exit (1);
		//TODO// } else {
		//TODO// 	cfg_setvar (item, itemno, value);
		//TODO// }
	}
}

void cfg_cachehost (char *item, int itemno, char *value) {
	int port;
	int ttl;
	if (cache == NULL) {
		//TODO// cache = memcached_create (NULL);
		//TODO// if (cache == NULL) {
			fprintf (stderr, "Failed to create memcached administrative structures\n");
			exit (1);
		//TODO// }
	}
	port = MEMCACHED_DEFAULT_PORT;
	if (configvars [CFGVAR_CACHE_PORT]) {
		port = atoi (configvars [CFGVAR_CACHE_PORT]);
	}
	//TODO// if (memcached_server_add (cache, value, port)) {
		fprintf (stderr, "Failed to add memcached server %s\n");
		exit (1);
	//TODO// }
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

char *cfg_tls_dhparamfile (void) {
	return configvars [CFGVAR_TLS_DHPARAMFILE];
}


