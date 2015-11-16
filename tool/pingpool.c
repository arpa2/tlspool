/* pingpool.c -- Show the input/output of a PING operation.
 *
 * From: Rick van Rein <rick@openfortress.nl>
 */


#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include <tlspool/commands.h>
#include <tlspool/starttls.h>


void print_pioc_ping (pingpool_t *pp, char *prefix) {
	char *date = pp->YYYYMMDD_producer;
	char *producer = date + 8;
	char facil [256];
	*facil = '\0';
	if (pp->facilities & PIOF_FACILITY_STARTTLS) {
		strcat (facil, ",starttls");
		pp->facilities &= ~PIOF_FACILITY_STARTTLS;
	}
	if (pp->facilities & PIOF_FACILITY_STARTGSS) {
		strcat (facil, ",startgss");
		pp->facilities &= ~PIOF_FACILITY_STARTGSS;
	}
	if (pp->facilities & PIOF_FACILITY_STARTSSH) {
		strcat (facil, ",startssh");
		pp->facilities &= ~PIOF_FACILITY_STARTSSH;
	}
	if (pp->facilities) {
		sprintf (facil + strlen (facil), ",0%08x", pp->facilities);
	}
	printf ("%s specdate: %.4s-%.2s-%.2s\n", prefix, date, date+4, date+6);
	printf ("%s specfrom: %s\n", prefix, producer);
	printf ("%s facility: %s\n", prefix, facil + 1);
}

int main (int argc, char *argv []) {
	char *sockpath = NULL;
	pingpool_t pp;

	if (argc > 2) {
		fprintf (stderr, "Usage: %s [socketfile]\n", argv [0]);
		exit (1);
	}
	if (argc == 2) {
		sockpath = argv [1];
	}

	memset (&pp, 0, sizeof (pp));
	strcpy (pp.YYYYMMDD_producer, TLSPOOL_IDENTITY_V2);
	pp.facilities = PIOF_FACILITY_ALL_CURRENT;
	printf ("\n");
	print_pioc_ping (&pp, "Client  ");
	printf ("\n");
	//
	// What we do now is not what any normal program should do; we ask
	// for all the facilities that the TLS Pool can provide.  That may
	// include things we never heard of, and may need to mention as an
	// integer flag value.  For a ping utility, that's useful, but for
	// any sane program it would be a bad example to follow.
	//
	pp.facilities = ~0L;
	if (tlspool_ping (&pp) < 0) {
		perror ("Failed to ping TLS Pool");
		exit (1);
	}
	print_pioc_ping (&pp, "TLS Pool");
	printf ("\n");
}

