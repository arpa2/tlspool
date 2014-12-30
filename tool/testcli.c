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
	.flags = 0,
	.local = 0,
	.ipproto = IPPROTO_TCP,
	.localid = "testcli@localhost",
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
			if (sz == -1) {
				break;
			} else if (sz == 0) {
				errno = 0;
				break;
			} else if (write (chanio, buf, sz, MSG_DONTWAIT) != sz) {
				break;
			}
		}
		if (inout [1].revents & POLLIN) {
			sz = read (chanio, buf, sizeof (buf), MSG_DONTWAIT);
			if (sz == -1) {
				break;
			} else if (sz == 0) {
				errno = 0;
				break;
			} else if (write (1, buf, sz, MSG_DONTWAIT) != sz) {
				break;
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
	plainfd = starttls_client (sox, &tlsdata_cli);
	if (plainfd == -1) {
		perror ("Failed to STARTTLS on testcli");
		exit (1);
	}
	printf ("DEBUG: STARTTLS succeeded on testcli\n");
	runterminal (plainfd);
	close (plainfd);
	printf ("DEBUG: Closed connection.  Waiting 2s to improve testing.\n");
	sleep (2);
	return 0;
}

