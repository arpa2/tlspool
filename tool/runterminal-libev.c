/* runterminal.c -- shared testing code loop for message loop */

/* runterminal-libev.c is a variant that uses libev instead of poll() */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include <unistd.h>
#include <poll.h>
#include <errno.h>
#include <signal.h>

#include <sys/socket.h>
#include <netinet/in.h>

#include <tlspool/starttls.h>

#include <ev.h>


int           chanio_global = -1;
starttls_t  *tlsdata_global = NULL;
uint32_t  startflags_global = 0;
const char  *localid_global = "";
const char *remoteid_global = "";


static void keys_cb (EV_P_ ev_io *evt, int revents) {
	ssize_t sz;
	char buf [512];
	if (revents & EV_ERROR) {
		ev_break (EV_A_ EVBREAK_ALL);
	}
	sz = read (0, buf, sizeof (buf));
	printf ("Read %ld bytes\n", sz);
	if (sz == -1) {
		ev_break (EV_A_ EVBREAK_ALL);
	} else if (sz == 0) {
		errno = 0;
		ev_break (EV_A_ EVBREAK_ALL);
	} else if (send (chanio_global, buf, sz, MSG_DONTWAIT) != sz) {
		ev_break (EV_A_ EVBREAK_ALL);
	} else {
		printf ("Sent %ld bytes\n", sz);
	}
}


static void chan_cb (EV_P_ ev_io *evt, int revents) {
	ssize_t sz;
	char buf [512];
	if (revents & EV_ERROR) {
		ev_break (EV_A_ EVBREAK_ALL);
	}
	sz = recv (chanio_global, buf, sizeof (buf), MSG_DONTWAIT);
	printf ("Received %ld bytes\n", sz);
	if (sz == -1) {
		ev_break (EV_A_ EVBREAK_ALL);
	} else if (sz == 0) {
		errno = 0;
		ev_break (EV_A_ EVBREAK_ALL);
	} else if (write (1, buf, sz) != sz) {
		ev_break (EV_A_ EVBREAK_ALL);
	} else {
		printf ("Printed %ld bytes\n", sz);
	}
}


static void cont_cb (EV_P_ ev_signal *sig, int revents) {
	if (revents & EV_ERROR) {
		ev_break (EV_A_ EVBREAK_ALL);
	}
	printf ("Received SIGCONT, will now initiate TLS handshake renegotiation\n");
	tlsdata_global->flags = startflags_global;
	if (localid_global)
		strcpy (tlsdata_global->localid, localid_global);
	if (remoteid_global)
		strcpy (tlsdata_global->remoteid, remoteid_global);
	if (-1 == tlspool_starttls (-1, tlsdata_global, NULL, NULL)) {
		printf ("TLS handshake renegotiation failed, terminating\n");
		ev_break (EV_A_ EVBREAK_ALL);
	}
	printf ("TLS handshake renegotiation completed successfully\n");
}


void runterminal (int chanio, int *sigcont, starttls_t *tlsdata,
		  uint32_t startflags, const char *localid, const char *remoteid) {
	struct ev_loop *loop = EV_DEFAULT;
	ev_io     keys;
	ev_io     chan;
	ev_signal cont;
	//
	// Make parameters tlsdata globally known (imperfect solution)
	chanio_global     = chanio;
	tlsdata_global    = tlsdata;
	startflags_global = startflags;
	localid_global    = localid;
	remoteid_global   = remoteid;
	//
	// Initialise event handler structures
	ev_io_init     (&keys, keys_cb, 0,      EV_READ);
	ev_io_init     (&chan, chan_cb, chanio, EV_READ);
	ev_signal_init (&cont, cont_cb, SIGCONT);
	//
	// Start event handlers
	ev_io_start     (loop, &keys);
	ev_io_start     (loop, &chan);
	ev_signal_start (loop, &cont);
	//
	// Run the event loop
	ev_run (loop, 0);
}
