/* tlspool/lidsel.c -- Simple demo of the localid selection API
 *
 * This API demo connects to the LID entry interface to the TLS Pool, and
 * guides the selection of local identities.  To that end, it prints any
 * database entries that are proposed, and it requests the entry of either
 * one of these by number, or of a complete local identity string.
 *
 * From: Rick van Rein <rick@openfortress.nl>
 */


#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include <syslog.h>
#include <errno.h>

#include <tlspool/starttls.h>
#include <tlspool/commands.h>


#ifndef MAXNUM_DB_LIDS
#   define MAXNUM_DB_LIDS 100
#endif


struct data {
	char dblids [MAXNUM_DB_LIDS] [128];
	int dblidctr;
};


/* The workhorse is the callback function.  It prints out database entries,
 * and stores them for future reference.  It also requests entry of the
 * local identity or the index number of the database entries printed.
 */
void lidcb (lidentry_t *entry, void *data) {
	//
	// Declare & initialise
	struct data *d = (struct data *) data;
	int error = 0;
	char input [128+1];
	char *inpastnum;
	long entryindex;
printf ("DEBUG: lidsel.c lidcb() called with localid %s\n", entry->localid);

	//
	// Handle database entries
	if (entry->flags & PIOF_LIDENTRY_DBENTRY) {
		entry->localid [127] = '\0';
		if (d->dblidctr < MAXNUM_DB_LIDS) {
			memcpy (d->dblids [d->dblidctr],
				entry->localid, 128);
			printf ("[%d] %s\n", d->dblidctr,
				entry->localid);
		}
		d->dblidctr++;
printf ("DEBUG: lidsel.c lidcb() returns after processing database entry\n");
		return;
	}

	//
	// Handle requests for localid
	if (d->dblidctr >= MAXNUM_DB_LIDS) {
		fprintf (stderr, "Overwhelmed by %d > %d entries\n",
				d->dblidctr, MAXNUM_DB_LIDS);
		d->dblidctr = MAXNUM_DB_LIDS;
	}
	entry->remoteid [127] = '\0';
	printf ("Remote identity: %s\n", entry->remoteid);
	do {
		error = 0;
		printf ("Please enter a local identity as a string, or by index:\n> ");
		fflush (stdout);
		fgets (input, 128, stdin);
		input [127] = '\0';
		if (input [0] == '\0') {
			; // Accept empty string as empty line
		} else if (input [strlen (input) -1] != '\n') {
			error = 1;
		} else {
			input [strlen (input) -1] = '\0';
		}
		if (input [0] == '\0') {
			memset (entry->localid, 0, 128);
			continue;	/* to loop end, return no entry */
		}
		entryindex = strtol (input, &inpastnum, 10);
		if (*inpastnum == '\0') {
			error = error || (entryindex < 0);
			error = error || (entryindex >= d->dblidctr);
			error = error || (entryindex >= MAXNUM_DB_LIDS);
			if (!error) {
				memcpy (entry->localid,
					d->dblids [entryindex], 128);
			}
		} else {
			memcpy (entry->localid,
				input, 128);
		}
	} while (error);
	d->dblidctr = 0;
printf ("DEBUG: lidsel.c lidcb() returns after setting localid to %s and flags to 0x%08lx\n", entry->localid, entry->flags);
	return;
}


int main (int argc, char *argv []) {
	//
	// Declare & initialise
	struct data data;
	data.dblidctr = 0;
	uint32_t regflags = PIOF_LIDENTRY_WANT_DBENTRY;
	int responsetime_sec = 300;
	int exitval;

	//
	// Parse cmdline args
	if (argc > 1) {
		fprintf (stderr, "Ignoring program arguments\n");
	}

	//
	// Open log, and also dump on stderr
	openlog ("lidsel", LOG_PID | LOG_PERROR | LOG_NDELAY, LOG_USER);

	//
	// Service the TLS Pool
	exitval = -tlspool_localid_service (NULL, regflags, responsetime_sec, lidcb, &data);
	if (exitval == 1) {
		perror ("localid entry service terminated");
	}

	//
	// Close the log facility
	closelog ();

	//
	// Return exitval
	return exitval;
}
