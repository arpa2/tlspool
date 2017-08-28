/* runterminal.c -- shared testing code loop for message loop */

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

void runterminal (int chanio, int *sigcont, starttls_t *tlsdata,
		  uint32_t startflags, const char *localid, const char *remoteid) {
	struct pollfd inout [2];
	ssize_t sz;
	char buf [512];
	inout [0].fd = 0;
	inout [1].fd = chanio;
	inout [0].events = inout [1].events = POLLIN;
	while (1) {
		if (*sigcont) {
			*sigcont = 0;
			printf ("Received SIGCONT, will now initiate TLS handshake renegotiation\n");
			tlsdata->flags = startflags;
			if (localid)
				strcpy (tlsdata->localid, localid);
			if (remoteid)
				strcpy (tlsdata->remoteid, remoteid);
			if (-1 == tlspool_starttls (-1, tlsdata, NULL, NULL)) {
				printf ("TLS handshake renegotiation failed, terminating\n");
				break;
			}
			printf ("TLS handshake renegotiation completed successfully\n");
		}
		if (poll (inout, 2, -1) == -1) {
			if (*sigcont) {
				continue;
			} else {
				break;
			}
		}
		if ((inout [0].revents | inout [1].revents) & ~POLLIN) {
			break;
		}
		if (inout [0].revents & POLLIN) {
			sz = read (0, buf, sizeof (buf));
			printf ("Read %ld bytes, sigcont==%d (should be 0 for proper operation)\n", sz, *sigcont);
			if (sz == -1) {
				break;
			} else if (sz == 0) {
				errno = 0;
				break;
			} else if (send (chanio, buf, sz, MSG_DONTWAIT) != sz) {
				break;
			} else {
				printf ("Sent %ld bytes\n", sz);
			}
		}
		if (inout [1].revents & POLLIN) {
			sz = recv (chanio, buf, sizeof (buf), MSG_DONTWAIT);
			printf ("Received %ld bytes, sigcont==%d (should be 0 for proper operation)\n", sz, *sigcont);
			if (sz == -1) {
				break;
			} else if (sz == 0) {
				errno = 0;
				break;
			} else if (write (1, buf, sz) != sz) {
				break;
			} else {
				printf ("Printed %ld bytes\n", sz);
			}
		}
	}
}
