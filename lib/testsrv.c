/* tlspool/testsrv.c -- Exchange plaintext stdio over the network */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include <tlspool/starttls.h>


static starttls_t tlsdata_srv = {
	.flags = 0,
	.local = 0,
	.ipproto = IPPROTO_TCP,
	.localid = "testsrv@localhost",
};


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
		plainfd = starttls_server (cnx, &tlsdata_srv, NULL);
		if (plainfd == -1) {
			perror ("Failed to STARTTLS on testsrv");
			exit (1);
		}
		printf ("DEBUG: STARTTLS succeeded on testsrv\n");
		sleep (5);
		close (cnx);
	}
	return 0;
}

