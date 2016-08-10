/* tool/set_trust.c -- Change trust anchor database values
 *
 * Provide a config and a hex-encoded key to change the trust settings as
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


const char const *usage =
"Usage: %s tlspool.conf flags aabbccdd valexp [infile.bin]\n"
" - tlspool.conf is the configuration file for the TLS Pool\n"
" - flags        selection of x509,pgp,revoke,pinned,client,server,notroot\n"
" - aabbccdd     is an anchor's key in hexadecimal notation\n"
" - valexp       is a validation expression for this entry\n"
" - infile.bin   optional input file with binary encoded anchor data\n"
"When the infile.bin argument is absent, the corresponding entry is deleted.\n";


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
	if ((*dbh)->open (*dbh, *txn, dbtad_fnm, NULL, DB_HASH, DB_CREATE | DB_THREAD, 0) != 0) {
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
	char *keystr = NULL;
	int hexlen;
	char *binfile = NULL;
	char *partstr = NULL;
	char *saveptr = NULL;
	char *valexp = NULL;
	uint8_t e_buf [5000];
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
	char *cfgfile;
	//
	// Sanity check
	if ((argc < 5) || (argc > 6)) {
		fprintf (stderr, usage, argv [0]);
		exit (1);
	}
	//
	// Initialise the modules taken from the src directory
	;
	//
	// Prepare variables from arguments
	cfgfile = argv [1];
	if (argc >= 6) {
		binfile = argv [5];
	}
	valexp = argv [4];
	keystr = argv [3];
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
	// Parse the hex string into a key value
	hexlen = strlen (argv [3]);
	if (hexlen & 0x0001) {
		fprintf (stderr, "Hexadecimal string with an odd number of digits\n");
		exit (1);
	}
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
	// Now modify the matching entries
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
		e_bindata = e_valexp + strnlen (e_valexp, e_value.size - 4) + 1;
		e_binlen = e_value.size - 4 - strnlen (e_valexp, e_value.size - 4) - 1;
		if (e_binlen <= 0) {
			fprintf (stderr, "Error retrieving binary data;\n");
		}
		printf ("Object flags are 0x%x\n", e_flags);
		if ((e_flags & 0xff) == (flags & 0xff)) {
			printf ("Deleting old entry 0x%x, %s, #%d\n",
				e_flags, e_valexp, e_binlen);
			if (crs->del (crs, 0) != 0) {
				fprintf (stderr, "Failed to delete record\n");
				crs->close (crs);
				goto failure;
			} else {
				printf ("Deleted this old record\n");
			}
		} else {
			printf ("Won't remove, type is 0x%x and not 0x%x\n",
				e_flags & 255, flags & 255);
		}
		nomore = crs->get (crs, &k_trust, &e_value, DB_NEXT_DUP);
	}
	crs->close (crs);
	if (nomore != DB_NOTFOUND) {
		fprintf (stderr, "Database error encountered while iterating\n");
		goto failure;
	}
	//
	// Now append any new values
	if (binfile != NULL) {
		int valexplen = strlen (valexp);
		if (stat (binfile, &statbuf) != 0) {
			fprintf (stderr, "Failed to stat %s: %s\n",
				binfile, strerror (errno));
			goto failure;
		}
		filesz = statbuf.st_size;
		if (4 + valexplen + 1 + filesz > sizeof (e_buf)) {
			fprintf (stderr, "Out of buffer memory trying to fill %s\n",
				binfile);
			goto failure;
		}
		* (uint32_t *) e_buf = htonl (flags);
		strcpy ((char *) & ((uint32_t *) e_buf) [1], valexp);
		fd = open (binfile, O_RDONLY);
		if (fd == -1) {
			fprintf (stderr, "Failed to open %s: %s\n",
				binfile, strerror (errno));
			goto failure;
		}
		if (read (fd, &e_buf [4 + valexplen + 1], filesz) != filesz) {
			fprintf (stderr, "Failed to read from %s: %s\n",
				binfile, strerror (errno));
			close (fd);
			goto failure;
		}
		close (fd);
		e_value.data = e_buf;
		e_value.size = 4 + valexplen + 1 + filesz;
		if (dbh->put (dbh, txn, &k_trust, &e_value, 0) != 0) {
			fprintf (stderr, "Failed to write record to database\n");
			goto failure;
		}
		printf ("Written the new record\n");
	}
	if (txn->commit (txn, 0) != 0) {
		fprintf (stderr, "Failed to commit transaction\n");
		exit (1);
	} else {
		fprintf (stderr, "Committed transaction\n");
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
