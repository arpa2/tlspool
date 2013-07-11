/* tlspool/service.c -- Main server routine for the TLS pool, socket handling */

#include <stdlib.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>


void run_service () {
	struct sockaddr_un sun;
	socklen_t sunlen = sizeof (sun);
	int srvsox = get_server_socket ();
	int appsox;
	while (appsox = accept (srvsox, (struct sockaddr *) &sun, &sunlen),
			appsox != -1) {
		printf ("DEBUG: Received incoming connection.  Closing it.\n");
		close (appsox);
	}
	perror ("Failed to accept on TLS pool socket");
	exit (1);
}
