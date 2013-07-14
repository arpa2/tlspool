/* tlspool/testcli.c -- Exchange plaintext stdio over the network */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <sys/socket.h>
#include <netinet/in.h>

#include <tlspool/starttls.h>


static starttls_t tlsdata_cli = {
	.flags = 0,
	.local = 0,
	.ipproto = IPPROTO_TCP,
	.localid = "testcli@localhost",
};


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
	sleep (1);
	close (plainfd);
	return 0;
}

