/* tlspool/config.c -- Parse & Process the configuration file */


#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <ctype.h>
#include <string.h>

#include <sys/socket.h>
#include <sys/types.h>
#include <sys/file.h>
#include <sys/un.h>

#include <fcntl.h>
#include <pwd.h>
#include <grp.h>

#include <ldap.h>

#include <gnutls/gnutls.h>
#include <gnutls/pkcs11.h>

#include <libmemcached/memcached.h>

static LDAP *ldap_handle;

static struct memcached_st *cache;

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
	//
	NULL,			NULL,		CFGVAR_NONE
};



void parse_cfgfile (char *filename) {
	FILE *cf = fopen (filename, "r");
	char line [514];
	int linelen;
	int eof = 0;
	char *here;
	struct cfgopt *curopt;
	int found;
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
	fprintf (stdout, "DEBUG: SETUP   %s AS %s\n", item, value);
}

void cfg_pidfile (char *item, int itemno, char *value) {
	static int fh = 0;
	if (fh) {
		fprintf (stderr, "You can specify only one PID file\n");
		exit (1);
	}
	cfg_setvar (item, CFGVAR_DAEMON_PIDFILE, value);
	fh = open (value, O_RDWR | O_CREAT, 0664);
	char pidbuf [10];
	if (fh < 0) {
		perror ("Failed to open PID file");
		exit (1);
	}
	if (flock (fh, LOCK_EX | LOCK_NB) != 0) {
		if (errno == EWOULDBLOCK) {
			bzero (pidbuf, sizeof (pidbuf));
			read (fh, pidbuf, sizeof (pidbuf)-1);
			fprintf (stderr, "Another daemon owns the PID file: process %s", pidbuf);
			exit (1);
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
	int len = strlen (value);
	int sox;
	uid_t me = getuid ();
	gid_t my = getgid ();
	if (len + 1 > sizeof (sun.sun_path)) {
		fprintf (stderr, "Socket path too long: %s\n", value);
		exit (1);
	}
	strcpy (sun.sun_path, value);
	len += sizeof (sun.sun_family);
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
	if (bind (sox, (struct sockaddr *) &sun, len) == -1) {
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
	fprintf (stdout, "DEBUG: DECLARE %s AS %s\n", item, value);
	struct passwd *pwd = getpwnam (value);
	if (!pwd) {
		fprintf (stderr, "Failed to find username %s\n", value);
		exit (1);
	}
	setuid (pwd->pw_uid);
}

void cfg_group (char *item, int itemno, char *value) {
	fprintf (stdout, "DEBUG: DECLARE %s AS %s\n", item, value);
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

static void free_p11pin (void) {
	char *pin = configvars [CFGVAR_PKCS11_PIN];
	if (pin) {
		bzero (pin, strlen (pin));
		free (pin);
		configvars [CFGVAR_PKCS11_PIN] = NULL;
	}
}

void cfg_p11path (char *item, int itemno, char *value) {
	fprintf (stdout, "DEBUG: DECLARE %s AS %s\n", item, value);
	cfg_setvar (item, itemno, value);
	free_p11pin ();
}

void cfg_p11token (char *item, int itemno, char *value) {
	unsigned int token_seq = 0;
	char *p11uri;
	fprintf (stdout, "DEBUG: DECLARE %s AS %s\n", item, value);
	if (!configvars [CFGVAR_PKCS11_PATH]) {
		fprintf (stderr, "You must specify pkcs11_path before any number of pkcs11_token\n");
		exit (1);
	}
	if (gnutls_pkcs11_add_provider (configvars [CFGVAR_PKCS11_PATH], NULL) != 0) {
		fprintf (stderr, "Failed to register PKCS #11 library with GnuTLS\n");
		exit (1);
	}
	while (gnutls_pkcs11_token_get_url (token_seq, 0, &p11uri) == 0) {
		printf ("DEBUG: Found token URI %s\n", p11uri);
		//TODO// if (gnutls_pkcs11_token_get_info (p11uri, GNUTLS_PKCS11_TOKEN_LABEL-of-SERIAL-of-MANUFACTURER-of-MODEL, output, utput_size) == 0) { ... }
		gnutls_free (p11uri);
		token_seq++;
	}
	//TODO// Select token by name (value)
	//TODO// if PIN available then set it up
	free_p11pin ();
}

void cfg_ldap (char *item, int itemno, char *value) {
	if (configvars [CFGVAR_LDAP_PROXY]) {
		fprintf (stderr, "This version ignores additional LDAP proxy servers\n");
	} else {
		ldap_handle = NULL;
		if (ldap_initialize (&ldap_handle, value) || !ldap_handle) {
			fprintf (stderr, "Failure to setup LDAP proxy server\n");
			exit (1);
		} else {
			cfg_setvar (item, itemno, value);
		}
	}
}

void cfg_cachehost (char *item, int itemno, char *value) {
	int port;
	int ttl;
	if (cache == NULL) {
		cache = memcached_create (NULL);
		if (cache == NULL) {
			fprintf (stderr, "Failed to create memcached administrative structures\n");
			exit (1);
		}
	}
	port = MEMCACHED_DEFAULT_PORT;
	if (configvars [CFGVAR_CACHE_PORT]) {
		port = atoi (configvars [CFGVAR_CACHE_PORT]);
	}
	if (memcached_server_add (cache, value, port)) {
		fprintf (stderr, "Failed to add memcached server %s\n");
		exit (1);
	}
}


