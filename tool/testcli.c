/* tlspool/testcli.c -- Exchange plaintext stdio over the network */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <poll.h>
#include <errno.h>

#include <sys/socket.h>
#include <netinet/in.h>

#include <tlspool/starttls.h>


static starttls_t tlsdata_cli = {
	.flags = 0x00000200,
	.local = 0,
	.ipproto = IPPROTO_TCP,
	.localid = "testcli@tlspool.arpa2.lab",
	.remoteid = "testsrv@tlspool.arpa2.lab",
};


void runterminal (int chanio) {
	struct pollfd inout [2];
	ssize_t sz;
	char buf [512];
	inout [0].fd = 0;
	inout [1].fd = chanio;
	inout [0].events = inout [1].events = POLLIN;
	while (1) {
		if (poll (inout, 2, -1) == -1) {
			break;
		}
		if ((inout [0].revents | inout [1].revents) & ~POLLIN) {
			break;
		}
		if (inout [0].revents & POLLIN) {
			sz = read (0, buf, sizeof (buf), MSG_DONTWAIT);
			printf ("Read %d bytes\n", sz);
			if (sz == -1) {
				break;
			} else if (sz == 0) {
				errno = 0;
				break;
			} else if (write (chanio, buf, sz, MSG_DONTWAIT) != sz) {
				break;
			} else {
				printf ("Sent %d bytes\n", sz);
			}
		}
		if (inout [1].revents & POLLIN) {
			sz = read (chanio, buf, sizeof (buf), MSG_DONTWAIT);
			printf ("Received %d bytes\n", sz);
			if (sz == -1) {
				break;
			} else if (sz == 0) {
				errno = 0;
				break;
			} else if (write (1, buf, sz, MSG_DONTWAIT) != sz) {
				break;
			} else {
				printf ("Printed %d bytes\n", sz);
			}
		}
	}
}


int main (int argc, char *argv) {
	int sox;
	int plainfd;
	struct sockaddr_in6 sin6;
	sox = socket (AF_INET6, SOCK_STREAM, 0);
	if (sox == -1) {
		perror ("Failed to create socket on testcli");
		exit (1);
	}
	bzero (&sin6, sizeof (sin6));
	sin6.sin6_family = AF_INET6;
	sin6.sin6_port = htons (12345);
	memcpy (&sin6.sin6_addr, &in6addr_loopback, 16);
	if (connect (sox, (struct sockaddr *) &sin6, sizeof (sin6)) == -1) {
		perror ("Socket failed to connect on testcli");
		exit (1);
	}
	plainfd = -1;
	if (-1 == starttls_client (sox, &tlsdata_cli, &plainfd, NULL)) {
		perror ("Failed to STARTTLS on testcli");
		if (plainfd >= 0) {
			close (plainfd);
		}
		exit (1);
	}
	printf ("DEBUG: STARTTLS succeeded on testcli\n");
	// Play around, just for fun, with the control key
	if (tlspool_control_reattach (tlsdata_cli.ctlkey) != -1) {
		printf ("ERROR: Could reattach before detaching the control?!?\n");
	}
	if (tlspool_control_detach (tlsdata_cli.ctlkey) == -1) {
		printf ("ERROR: Could not detach the control?!?\n");
	}
	if (tlspool_control_detach (tlsdata_cli.ctlkey) != -1) {
		printf ("ERROR: Could detach the control twice?!?\n");
	}
	if (tlspool_control_reattach (tlsdata_cli.ctlkey) == -1) {
		printf ("ERROR: Could not reattach the control?!?\n");
	}
	if (tlspool_control_reattach (tlsdata_cli.ctlkey) != -1) {
		printf ("ERROR: Could reattach the control twice?!?\n");
	}
	printf ("DEBUG: Local plainfd = %d\n", plainfd);
	runterminal (plainfd);
	close (plainfd);
	printf ("DEBUG: Closed connection.  Waiting 2s to improve testing.\n");
	sleep (2);
	return 0;
}

