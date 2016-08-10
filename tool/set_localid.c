/* tool/set_localid.c -- Add local identity credential
 *
 * Provide a config, a NAI and a type of credential.  The command erases all
 * old entries that match and replaces them with what is provided, if anything.
 * The provided information should be a PKCS #11 URI and a binary file holding
 * public credentials (not a base64 / Armoured / PEM notation).
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
"Usage: %s tlspool.conf [user@]fqdn type [p11priv pubdata...]\n"
" - tlspool.conf      is the configuration file for the TLS Pool\n"
" - user@fqdn or fqdn is a network access identifier\n"
" - type              X.509,OpenPGP,valexp,client,server,nop11,chained\n"
" - p11priv           is a PKCS #11 URI string for the private key\n"
" - pubdata           is a file name    string for the public key package\n"
"The pairs of p11priv and pubdata replace the old content.  An empty list of\n"
"pairs is nothing special; it replaces the old content with zero entries.\n";


struct typemap_t {
	char *name;
	uint32_t bits;
};

struct typemap_t typemap [] = {
	{ "X.509",	1 },
	{ "x509",	1 },
	{ "OpenPGP",	2 },
	{ "valexp",     5 },
	{ "cli",	256 },
	{ "srv",	512 },
	{ "client",	256 },
	{ "server",	512 },
	{ "noP11",	4096 },
	{ "chained",	8192 },
	{ NULL,		0 }
};


/* Setup and tear down management */
int setup_management (char *cfgfile, DB_ENV **dbenv, DB_TXN **txn, DB **dbh) {
	char *dbenv_dir = tlspool_configvar (cfgfile, "dbenv_dir");
	char *dblid_fnm = tlspool_configvar (cfgfile, "db_localid");
	if (dbenv_dir == NULL) {
		fprintf (stderr, "Please configure database environment directory\n");
		return 0;
	}
	if (dblid_fnm == NULL) {
		fprintf (stderr, "Please configure localid database name\n");
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
		fprintf (stderr, "Failed to create localid database\n");
		return 0;
	}
	if ((*dbh)->set_flags (*dbh, DB_DUP) != 0) {
		fprintf (stderr, "Failed to setup localid database for duplicate entries\n");
		return 0;
	}
	if ((*dbh)->open (*dbh, *txn, dblid_fnm, NULL, DB_HASH, DB_CREATE | DB_THREAD, 0) != 0) {
		fprintf (stderr, "Failed to open localid database\n");
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
	char *localid = NULL;
	char *partstr = NULL;
	char *saveptr = NULL;
	char *p11uri = NULL;
	uint8_t e_buf [5000];
	int argi = argc;
	int filesz = 0;
	int p11len = 0;
	struct stat statbuf;
	uint32_t flags = 0;
	DB_ENV *dbenv;
	DB_TXN *txn;
	DB *dbh;
	DBC *crs;
	DBT k_localid;
	DBT e_value;
	int nomore;
	int fd;
	char *cfgfile;
	//
	// Sanity check
	if ((argc < 4) || ((argc % 2) != 0)) {
		fprintf (stderr, usage, argv [0]);
		exit (1);
	}
	//
	// Initialise the modules taken from the src directory
	;
	//
	// Prepare variables from arguments
	cfgfile = argv [1];
	localid = argv [2];
	partstr = strtok_r (argv [3], ",", &saveptr);
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
	if ((flags & 0x000000ff) != 5) {
		argi = 4;
		while (argi < argc) {
			if (strncmp (argv [argi], "pkcs11:", 7) != 0) {
				fprintf (stderr, "PKCS #11 URIs must start with \"pkcs11:\"\n");
				exit (1);
			}
			argi += 2;
		}
	}
	//
	// Now modify the matching entries
	if (!setup_management (cfgfile, &dbenv, &txn, &dbh)) {
		exit (1);
	}
	if (dbh->cursor (dbh, txn, &crs, 0) != 0) {
		fprintf (stderr, "Failed to open cursor on localid.db\n");
		goto failure;
	}
	memset (&k_localid, 0, sizeof (k_localid));
	k_localid.data = localid;
	k_localid.size = strlen (localid);
	nomore = crs->get (crs, &k_localid, &e_value, DB_SET);
	while (nomore == 0) {
		uint32_t e_flags = 0;
		char *e_p11uri = NULL;
		uint8_t *e_bindata;
		int e_binlen;
		if (e_value.size < 4) {
			fprintf (stderr, "Found too-short entry?!?\n");
			crs->close (crs);
			goto failure;
		}
		e_flags = ntohl (* (uint32_t *) e_value.data);
		e_p11uri = (char *) & ((uint32_t *) e_value.data) [1];
		e_bindata = e_p11uri + strnlen (e_p11uri, e_value.size - 4) + 1;
		e_binlen = e_value.size - 4 - strnlen (e_p11uri, e_value.size - 4) - 1;
		if (e_binlen <= 0) {
			fprintf (stderr, "Error retrieving binary data;\n");
		}
		printf ("Object flags are 0x%x\n", e_flags);
		if ((e_flags & 0xff) == (flags & 0xff)) {
			printf ("Deleting old entry 0x%x, %s, #%d\n",
				e_flags, e_p11uri, e_binlen);
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
		nomore = crs->get (crs, &k_localid, &e_value, DB_NEXT_DUP);
	}
	crs->close (crs);
	if (nomore != DB_NOTFOUND) {
		fprintf (stderr, "Database error encountered while iterating\n");
		goto failure;
	}
	//
	// Now append any new values
	argi = 4;
	while (argi < argc) {
		p11len = strlen (argv [argi]);
		if (stat (argv [argi+1], &statbuf) != 0) {
			fprintf (stderr, "Failed to stat %s: %s\n",
				argv [argi+1], strerror (errno));
			goto failure;
		}
		filesz = statbuf.st_size;
		if (4 + p11len + 1 + filesz > sizeof (e_buf)) {
			fprintf (stderr, "Out of buffer memory trying to fill %s\n",
				argv [argi]);
			goto failure;
		}
		* (uint32_t *) e_buf = htonl (flags);
		strcpy ((char *) & ((uint32_t *) e_buf) [1], argv [argi]);
		fd = open (argv [argi+1], O_RDONLY);
		if (fd == -1) {
			fprintf (stderr, "Failed to open %s: %s\n",
				argv [argi+1], strerror (errno));
			goto failure;
		}
		if (read (fd, &e_buf [4 + p11len + 1], filesz) != filesz) {
			fprintf (stderr, "Failed to read from %s: %s\n",
				argv [argi+1], strerror (errno));
			close (fd);
			goto failure;
		}
		close (fd);
		e_value.data = e_buf;
		e_value.size = 4 + p11len + 1 + filesz;
		if (dbh->put (dbh, txn, &k_localid, &e_value, 0) != 0) {
			fprintf (stderr, "Failed to write record to database\n");
			goto failure;
		}
		printf ("Written %s and %s\n", argv [argi], argv [argi+1]);
		argi += 2;
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
