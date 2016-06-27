/* pulleyback/connect.c -- Parse the configuration, connect to a database
 *
 * Copied from src/config.c
 *
 * From: Rick van Rein <rick@openfortress.nl>
 */


#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include <fcntl.h>
#include <sys/stat.h>

#include <db.h>

#include "poolback.h"


/* General configfile parser; returns 0 for success, -1 for error
 */
static int parse_cfgfile (struct pulleyback_tlspool *self) {
	FILE *cf;
	char line [514];
	int linelen;
	int eof = 0;
	char *here;
	int found;
	self->db_env = NULL;
	self->db_filename = NULL;
	if (self->config == NULL) {
		return -1;
	}
	cf = fopen (self->config, "r");
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
		if (strcmp (line, "dbenv_dir") == 0) {
			if (self->db_env == NULL) {
				self->db_env = strdup (here);
			}
		} else if ((strncmp (line, "db_", 3) == 0)
				&& (strcmp (line + 3, self->type) == 0)) {
			if (self->db_filename == NULL) {
				self->db_filename = strdup (here);
			}
		}
	}
	fclose (cf);
	if ((self->db_env == NULL) || (self->db_filename == NULL)) {
		return -1;
	}
	return 0;
}

/* Close the database environment.
 */
void close_database (struct pulleyback_tlspool *self) {
	if (self->db != NULL) {
		if (0 != self->db->close (self->db, 0)) {
			fprintf (stderr, "Failed to close database\n");
		}
		self->db = NULL;
	}
	if (self->env != NULL) {
		if (0 != self->env->close (self->env, 0)) {
			fprintf (stderr, "Failed to close database environment\n");
		}
		self->env = NULL;
	}
}

/* Open a database environment and a database file.  Returns 0 for succes,
 * or -1 for error.
 */
int open_database (struct pulleyback_tlspool *self) {
	self->env = NULL;
	self->db  = NULL;
	self->txn = NULL;
	parse_cfgfile (self);
	if ((self->db_env == NULL) || (self->db_filename == NULL)) {
		return -1;
	}
	//
	// Create the database environment
	if (0 != db_env_create (&self->env, 0)) {
		self->env = NULL;
		goto error;
	}
	if (0 != self->env->open (self->env, self->db_env, DB_CREATE | DB_RECOVER | DB_INIT_TXN | DB_INIT_LOG | DB_INIT_LOCK | DB_THREAD | DB_INIT_MPOOL, S_IRUSR | S_IWUSR)) {
		goto error;
	}
	//
	// Access the database
	if (0 != db_create (&self->db, self->env, 0)) {
		goto error;
	}
	if (0 != self->db->set_flags (self->db, DB_DUP)) {
		goto error;
	}
	if (0 != self->db->open (self->db, NULL /* TODO:transactions?!? */, self->db_filename, NULL, DB_HASH, DB_THREAD | DB_AUTO_COMMIT, 0)) {
		goto error;
	}
	//
	// Return success
	return 0;
	//
	// Cleanup and error return
error:
	close_database (self);
	return -1;
}

