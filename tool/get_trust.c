/* tool/get_trust.c -- Retrieve local identity credentials
 *
 * Provide a config and a hex-encoded key to see what trust settings are
 * defined in trust.db.
 *
 * From: Rick van Rein <rick@openfortress.nl>
 */


#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <sys/types.h>
#include <sys/stat.h>

#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

#include <arpa/inet.h>

#include <db.h>

#include <tlspool/internal.h>


const char usage[] =
"Usage: %s tlspool.conf flags aabbccdd [outfile.bin]\n"
" - tlspool.conf is the configuration file for the TLS Pool\n"
" - flags        selection of x509,pgp,revoke,pinned,client,server,notroot\n"
" - aabbccdd     is an anchor's key in hexadecimal notation\n"
" - outfile.bin  optional output file for binary encoded anchor data\n"
"Since the anchor data is stored in a binary format, it will never be printed\n"
"on stdout; in absense of outfile.bin the value is simply not output.\n";


struct typemap_t {
	char *name;
	uint32_t bits;
};

struct typemap_t typemap [] = {
	{ "x509",	1 },
	{ "pgp",	2 },
	{ "client",	256 },
	{ "server",	512 },
	{ "revoke",	1024 },
	{ "pinned",	2048 },
	{ "notroot",	65536 },
	{ NULL,		0 }
};


/* Setup and tear down management */
int setup_management (char *cfgfile, DB_ENV **dbenv, DB_TXN **txn, DB **dbh) {
	char *dbenv_dir = tlspool_configvar (cfgfile, "dbenv_dir");
	char *dbtad_fnm = tlspool_configvar (cfgfile, "db_trust");
	if (dbenv_dir == NULL) {
		fprintf (stderr, "Please configure database environment directory\n");
		return 0;
	}
	if (dbtad_fnm == NULL) {
		fprintf (stderr, "Please configure trust database name\n");
		return 0;
	}
	if (db_env_create (dbenv, 0) != 0) {
		fprintf (stderr, "Failed to create database environment");
		return 0;
	}
	if ((*dbenv)->open (*dbenv, dbenv_dir, DB_CREATE | DB_RECOVER | DB_INIT_TXN | DB_INIT_LOG | DB_INIT_LOCK | DB_THREAD | DB_INIT_MPOOL, S_IRUSR | S_IWUSR) != 0) {
		fprintf (stderr, "Failed to open database environment");
		return 0;
	}
	if ((*dbenv)->txn_begin (*dbenv, NULL, txn, 0) != 0) {
		fprintf (stderr, "Failed to start transaction\n");
		exit (1);
	}
	if (db_create (dbh, *dbenv, 0) != 0) {
		fprintf (stderr, "Failed to create trust database\n");
		return 0;
	}
	if ((*dbh)->set_flags (*dbh, DB_DUP) != 0) {
		fprintf (stderr, "Failed to setup trust database for duplicate entries\n");
		return 0;
	}
	if ((*dbh)->open (*dbh, *txn, dbtad_fnm, NULL, DB_HASH, DB_THREAD | DB_RDONLY, 0) != 0) {
		fprintf (stderr, "Failed to open trust database\n");
		return 0;
	}
	return 1;
}

/* Cleanup maangement structures */
void cleanup_management (DB_ENV *dbenv, DB *db) {
	db->close (db, 0);
	dbenv->close (dbenv, 0);
}

int main (int argc, char *argv []) {
	char *trust = NULL;
	char *partstr = NULL;
	char *saveptr = NULL;
	char *valexp = NULL;
	uint8_t e_buf [5000];
	int hexlen;
	int argi = argc;
	int filesz = 0;
	struct stat statbuf;
	uint32_t flags = 0;
	DB_ENV *dbenv;
	DB_TXN *txn;
	DB *dbh;
	DBC *crs;
	DBT k_trust;
	DBT e_value;
	int nomore;
	int fd;
	int outfile = -1;
	int written = 0;
	char *cfgfile;
	//
	// Sanity check
	if ((argc < 4) || (argc > 5)) {
		fprintf (stderr, usage, argv [0]);
		exit (1);
	}
	if (argc == 5) {
		outfile = open (argv [4], O_WRONLY | O_CREAT | O_TRUNC, 0644);
		if (outfile < 0) {
			perror ("Failed to open output file");
			exit (1);
		}
	}
	hexlen = strlen (argv [3]);
	if (hexlen & 0x0001) {
		fprintf (stderr, "Hexadecimal string with an odd number of digits\n");
		exit (1);
	}
	//
	// Parse the hex string into a key value
	uint8_t keybytes [hexlen >> 1];
	char hexchars [3];
	int i;
	hexchars [2] = '\0';
	for (i=0; i<hexlen; i+=2) {
		hexchars [0] = argv [3] [i + 0];
		hexchars [1] = argv [3] [i + 1];
		keybytes [i >> 1] = strtol (hexchars, &saveptr, 16);
		if (saveptr != &hexchars [2]) {
			fprintf (stderr, "Illegal character in hex byte: 0x%s\n", hexchars);
			exit (1);
		}
	}
	//
	// Initialise the modules taken from the src directory
	;
	//
	// Prepare variables from arguments
	cfgfile = argv [1];
	partstr = strtok_r (argv [2], ",", &saveptr);
	if (partstr == NULL) {
		fprintf (stderr, "Flags must not be empty\n");
		exit (1);
	}
	while (partstr != NULL) {
		struct typemap_t *walker = typemap;
		while (walker->name != NULL) {
			if (strcasecmp (walker->name, partstr) == 0) {
				flags |= walker->bits;
				break;
			}
			walker++;
		}
		if (walker->name == NULL) {
			fprintf (stderr, "Flag name %s not recognised\n", partstr);
			exit (1);
		}
		partstr = strtok_r (NULL, ",", &saveptr);
	}
	//
	// Now retrieve the matching entries
	if (!setup_management (cfgfile, &dbenv, &txn, &dbh)) {
		exit (1);
	}
	if (dbh->cursor (dbh, txn, &crs, 0) != 0) {
		fprintf (stderr, "Failed to open cursor on trust.db\n");
		goto failure;
	}
	bzero (&k_trust, sizeof (k_trust));
	k_trust.data = keybytes;
	k_trust.size = hexlen >> 1;
	nomore = crs->get (crs, &k_trust, &e_value, DB_SET);
	while (nomore == 0) {
		uint32_t e_flags = 0;
		char *e_valexp = NULL;
		uint8_t *e_bindata;
		int e_binlen;
		if (e_value.size < 4) {
			fprintf (stderr, "Found too-short entry?!?\n");
			crs->close (crs);
			goto failure;
		}
		e_flags = ntohl (* (uint32_t *) e_value.data);
		e_valexp = (char *) & ((uint32_t *) e_value.data) [1];
		e_bindata = (uint8_t *)(e_valexp + strnlen (e_valexp, e_value.size - 4) + 1);
		e_binlen = e_value.size - 4 - strnlen (e_valexp, e_value.size - 4) - 1;
		if (e_binlen <= 0) {
			fprintf (stderr, "Error retrieving binary data\n");
			crs->close (crs);
			goto failure;
		}
		if ((e_flags & 0xff) == (flags & 0xff)) {
			uint32_t todo_flags = e_flags;
			struct typemap_t *tm = typemap;
			printf ("Flags: 0x%x:", e_flags);
			while (tm->name != NULL) {
				if (todo_flags & tm->bits) {
					printf (" %s", tm->name);
					todo_flags = todo_flags & ~tm->bits;
				}
				tm++;
			}
			if (todo_flags != 0) {
				printf (" UNKNOWN_%d", todo_flags);
			}
			printf ("\nValidation expression: %s\n", e_valexp);
			written = 0;
			if (outfile >= 0) {
				if (write (outfile, e_bindata, e_binlen) == e_binlen) {
printf ("Written %d bytes\n", e_binlen);
					written = 1;
				}
				close (outfile);
				outfile = -1;	// No more than one binary write
			}
			printf ("Binary data: %02x %02x...%02x %02x (length %d)%s\n",
				e_bindata [0], e_bindata [1],
				e_bindata [e_binlen-2], e_bindata [e_binlen-1],
				e_binlen,
				written? " (written)": "");
		}
		nomore = crs->get (crs, &k_trust, &e_value, DB_NEXT_DUP);
	}
	crs->close (crs);
	if (nomore != DB_NOTFOUND) {
		fprintf (stderr, "Database error encountered while iterating\n");
		goto failure;
	}
	if (txn->commit (txn, 0) != 0) {
		fprintf (stderr, "Failed to commit readonly transaction\n");
		exit (1);
	}
	//
	// Finish up and report success
success:
	cleanup_management (dbenv, dbh);
	return 0;
	//
	// Handle failure during database interactions
failure:
	fprintf (stderr, "Rolling back transaction\n");
	txn->abort (txn);
	cleanup_management (dbenv, dbh);
	exit (1);
}
