/* tlspool/testsrv.c -- Exchange plaintext stdio over the network */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <poll.h>
#include <errno.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include <tlspool/starttls.h>


static starttls_t tlsdata_srv = {
	.flags = PIOF_STARTTLS_LOCALROLE_SERVER
		| PIOF_STARTTLS_REMOTEROLE_CLIENT,
	.local = 0,
	.ipproto = IPPROTO_TCP,
	.localid = "testsrv@tlspool.arpa2.lab",
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
	int sox, cnx;
	int plainfd;
	struct sockaddr_in6 sin6;
	sox = socket (AF_INET6, SOCK_STREAM, 0);
	if (sox == -1) {
		perror ("Failed to create socket on testsrv");
		exit (1);
	}
	bzero (&sin6, sizeof (sin6));
	sin6.sin6_family = AF_INET6;
	sin6.sin6_port = htons (12345);
	memcpy (&sin6.sin6_addr, &in6addr_loopback, 16);
	if (bind (sox, (struct sockaddr *) &sin6, sizeof (sin6)) == -1) {
		perror ("Socket failed to bind on testsrv");
		exit (1);
	}
	if (listen (sox, 5) == -1) {
		perror ("Socket failed to listen on testsrv");
		exit (1);
	}
	while (cnx = accept (sox, NULL, 0)) {
		if (cnx == -1) {
			perror ("Failed to accept incoming connection");
			continue;
		}
		plainfd = -1;
		if (-1 == tlspool_starttls (cnx, &tlsdata_srv, &plainfd, NULL)) {
			perror ("Failed to STARTTLS on testsrv");
			if (plainfd >= 0) {
				close (plainfd);
			}
			exit (1);
		}
		printf ("DEBUG: STARTTLS succeeded on testsrv\n");
		printf ("DEBUG: Local plainfd = %d\n", plainfd);
		runterminal (plainfd);
		printf ("DEBUG: Client connection terminated\n");
		close (plainfd);
	}
	return 0;
}

