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
void lidcb (struct tlspool_command *tc, void *data) {
	//
	// Declare & initialise
	struct data *d = (struct data *) data;
	int error = 0;
	char input [128+1];
	char *inpastnum;
	long entryindex;
printf ("DEBUG: lidsel.c lidcb() called with localid %s\n", tc->pio_data.pioc_lidentry.localid);

	//
	// Sanity checking
	if (tc->pio_cmd != PIOC_LIDENTRY_CALLBACK_V2) {
		tc->pio_cmd = PIOC_ERROR_V1;
		tc->pio_data.pioc_error.tlserrno = EINVAL;
		strcpy (tc->pio_data.pioc_error.message,
			"Local identity callback did not recognise command");
printf ("DEBUG: lidsel.c lidcb() returns on command error\n");
		return;
	}

	//
	// Handle database entries
	if (tc->pio_data.pioc_lidentry.flags & PIOF_LIDENTRY_DBENTRY) {
		tc->pio_data.pioc_lidentry.localid [127] = '\0';
		if (d->dblidctr < MAXNUM_DB_LIDS) {
			memcpy (d->dblids [d->dblidctr],
				tc->pio_data.pioc_lidentry.localid, 128);
			printf ("[%d] %s\n", d->dblidctr,
				tc->pio_data.pioc_lidentry.localid);
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
	tc->pio_data.pioc_lidentry.remoteid [127] = '\0';
	printf ("Remote identity: %s\n", tc->pio_data.pioc_lidentry.remoteid);
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
			memset (tc->pio_data.pioc_lidentry.localid, 0, 128);
			continue;	/* to loop end, return no entry */
		}
		entryindex = strtol (input, &inpastnum, 10);
		if (*inpastnum == '\0') {
			error = error || (entryindex < 0);
			error = error || (entryindex >= d->dblidctr);
			error = error || (entryindex >= MAXNUM_DB_LIDS);
			if (!error) {
				memcpy (tc->pio_data.pioc_lidentry.localid,
					d->dblids [entryindex], 128);
			}
		} else {
			memcpy (tc->pio_data.pioc_lidentry.localid,
				input, 128);
		}
	} while (error);
	d->dblidctr = 0;
printf ("DEBUG: lidsel.c lidcb() returns after setting localid to %s and flags to 0x%08lx\n", tc->pio_data.pioc_lidentry.localid, tc->pio_data.pioc_lidentry.flags);
	return;
}


int main (int argc, char *argv []) {
	//
	// Declare & initialise
	struct data data;
	data.dblidctr = 0;
	uint32_t regflags = PIOF_LIDENTRY_DBENTRY;
	int responsetime_sec = 300;

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
	tlspool_localid_service (regflags, responsetime_sec, lidcb, &data);
	fprintf (stderr, "The local identity callback registration was ended\n");

	//
	// Close the log facility
	closelog ();

	//
	// Return succes
	return 0;
}
