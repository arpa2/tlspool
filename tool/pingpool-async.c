/* pingpool.c -- Show the input/output of a PING operation.
 *
 * From: Rick van Rein <rick@openfortress.nl>
 */


#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <assert.h>

#include <tlspool/commands.h>
#include <tlspool/async.h>


void print_pioc_ping (pingpool_t *pp, char *prefix) {
	char *date = pp->YYYYMMDD_producer;
	char *producer = date + 8;
	char facil [256];
	facil [0] = facil [1] = '\0';
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


volatile bool callback_done = false;

void cb_ping_done (struct tlspool_async_request *cbdata, int opt_fd) {
	assert (opt_fd < 0);
	callback_done = true;
}


int main (int argc, char *argv []) {
	char *sockpath = NULL;
	struct tlspool_async_pool mypool;
	struct tlspool_async_request myreq;
	pingpool_t *pp = &myreq.cmd.pio_data.pioc_ping;

	if (argc > 2) {
		fprintf (stderr, "Usage: %s [socketfile]\n", argv [0]);
		exit (1);
	}
	if (argc == 2) {
		sockpath = argv [1];
	}
	assert (tlspool_async_open (&mypool, sizeof (struct tlspool_command), sockpath, true));
	print_pioc_ping (&mypool.pingdata, "Initial ");
	printf ("\n");

	memset (&myreq, 0, sizeof (myreq));
	strcpy (pp->YYYYMMDD_producer, TLSPOOL_IDENTITY_V2);
	pp->facilities = PIOF_FACILITY_ALL_CURRENT;
	printf ("\n");
	print_pioc_ping (pp, "Client  ");
	printf ("\n");
	//
	// We now setup the request, and allow it to callback to us.
	// We will loop until this has happened, which is not the best
	// programming practice, but alright for a simple demonstration.
	// In production use, we should of course use locks.
	//
	myreq.cmd.pio_cmd = PIOC_PING_V2;
	myreq.cbfunc = cb_ping_done;
	pp->facilities = ~0L;
	//
	// What we do now is not what any normal program should do; we ask
	// for all the facilities that the TLS Pool can provide.  That may
	// include things we never heard of, and may need to mention as an
	// integer flag value.  For a ping utility, that's useful, but for
	// any sane program it would be a bad example to follow.
	//
	assert (tlspool_async_request (&mypool, &myreq, -1));
	while (!callback_done) {
		tlspool_async_process (&mypool);
	}
	print_pioc_ping (pp, "TLS Pool");
	printf ("\n");

	assert (tlspool_async_close (&mypool, true));

	return 0;
}

