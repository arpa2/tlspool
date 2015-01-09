/* tlspool/tlstunnel.c -- Simple utility, forward TLS as TCP and vice versa */

#include <stdlib.h>
#include <stdio.h>
#include <stdio.h>
#include <string.h>

#include <errno.h>
#include <poll.h>
#include <unistd.h>
#include <getopt.h>

#include <arpa/inet.h>
#include <netinet/in.h>

#include <tlspool/starttls.h>


static starttls_t tlsdata = {
	.flags = 0,
	.local = 0,
};


struct copydata {
	pthread_t thread;
	int cnx;
	int fwd;
};


void copycat (void *cd_void) {
	struct copydata *cd = (struct copydata *) cd_void;
	struct pollfd inout [2];
	char buf [1024];
	ssize_t sz;
	inout [0].fd = cd->cnx;
	inout [1].fd = cd->fwd;
	inout [0].events = inout [1].events = POLLIN;
	printf ("DEBUG: Starting copycat cycle for insox=%d, fwsox=%d\n", cd->cnx, cd->fwd);
	while (1) {
		if (poll (inout, 2, -1) == -1) {
			printf ("DEBUG: Copycat polling returned an error\n");
			break;
		}
		if (inout [0].revents & POLLIN) {
			sz = recv (cd->cnx, buf, sizeof (buf), MSG_DONTWAIT);
			printf ("DEBUG: Copycat received %d local bytes from %d\n", (int) sz, cd->cnx);
			if (sz == -1) {
				break;	// stream error
			} else if (sz == 0) {
				errno = 0;
				break;	// orderly shutdown
			} else if (send (cd->fwd, buf, sz, MSG_DONTWAIT) != sz) {
				break;	// communication error
			} else {
				printf ("Copycat forwarded %d bytes to %d\n", (int) sz, cd->fwd);
			}
		}
		if (inout [1].revents & POLLIN) {
			sz = recv (cd->fwd, buf, sizeof (buf), MSG_DONTWAIT);
			printf ("DEBUG: Copycat received %d reply bytes from %d\n", (int) sz, cd->fwd);
			if (sz == -1) {
				break;	// stream error
			} else if (sz == 0) {
				errno = 0;
				break;	// orderly shutdown
			} else if (send (cd->cnx, buf, sz, MSG_DONTWAIT) != sz) {
				break;	// communication error
			} else {
				printf ("Copycat returned %d bytes to %d\n", (int) sz, cd->cnx);
			}
		}
		if ((inout [0].revents | inout [1].revents) & ~POLLIN) {
			printf ("DEBUG: Copycat polling returned a special condition\n");
			break;
		}
	}
	printf ("DEBUG: Ending copycat cycle for insox=%d, fwsox=%d\n", cd->cnx, cd->fwd);
	close (cd->cnx);
	close (cd->fwd);
	free (cd);	// Contains pthread_t but that's only an ID
}


int str2port (char *portstr) {
	char *portrest;
	long int retval = strtol (portstr, &portrest, 0);
	if (*portrest) {
		fprintf (stderr, "Not a port number: %s\n", portstr);
		exit (1);
	}
	if ((retval <= 0) || (retval > 65535)) {
		fprintf (stderr, "Port numbers range from 1 to 65535: %s\n", portstr);
		exit (1);
	}
	return (int) retval;
}


int main (int argc, char *argv []) {
	int parsing = 1;
	int carrier = -1;
	int dtls = 0;
	int role = -1;
	int stream;
	struct sockaddr_in6 insa = { .sin6_family = AF_INET6, 0 };
	struct sockaddr_in6 fwsa = { .sin6_family = AF_INET6, 0 };
	char *localid = NULL;
	char *remotid = NULL;
	char *cmdsoxpath = NULL;
	int sox = -1;
	//
	// Parse the command line arguments
	while (parsing) {
		//TODO// getlongopt
		int opt = getopt (argc, argv, "csutx:y:L:R:S:");
		switch (opt) {
		case 'c':
		case 's':
			if (role != -1) {
				fprintf (stderr, "Specify -c or -s only once\n");
				exit (1);
			}
			role = opt;
			break;
		case 'u':
			fprintf (stderr, "UDP mode wrapping with DTLS is not implemented -- see man page\n");
			exit (1);
		case 't':
		case 'x':
		case 'y':
			if (carrier != -1) {
				fprintf (stderr, "Specify -t or -x or -y only once\n");
				exit (1);
			}
			carrier = opt;
			if ((carrier == 'x') || (carrier == 'y')) {
				long int parsed = strtol (optarg, &optarg, 0);
				if (*optarg) {
					fprintf (stderr, "Syntax error in stream number to -%d\n", opt);
					exit (1);
				}
				if ((parsed < 0) || (parsed > 65535)) {
					fprintf (stderr, "Stream numbers range from 0 to 65535\n");
					exit (1);
				}
				stream = parsed;
			}
			break;
		case 'L':
			if (*tlsdata.localid) {
				fprintf (stderr, "For now, it is not permitted to specify multiple local identities\n");
				exit (1);
			}
			if (1 + strlen (optarg) > sizeof (tlsdata.localid)) {
				fprintf (stderr, "Local identity is too long\n");
				exit (1);
			}
			strcpy (tlsdata.localid, optarg);
			break;
		case 'R':
			if (*tlsdata.remoteid) {
				fprintf (stderr, "Cannot constrain to multiple remote identities at the same time\n");
				exit (1);
			}
			if (1 + strlen (optarg) > sizeof (tlsdata.remoteid)) {
				fprintf (stderr, "Remote identity is too long\n");
				exit (1);
			}
			strcpy (tlsdata.remoteid, optarg);
			break;
		case 'S':
			if (cmdsoxpath) {
				fprintf (stderr, "You can specify only one TLS Pool command socket path\n");
				exit (1);
			}
			cmdsoxpath = strdup (optarg);
			break;
		case -1:
			parsing = 0;
		}
	}
	if (role == -1) {
		fprintf (stderr, "Specify either -c or -s\n");
		exit (1);
	}
	if (!*tlsdata.localid) {
		fprintf (stderr, "You need to specify -L\n");
		exit (1);
	}
	if (argc != optind + 4) {
		fprintf (stderr, "After options, specify: inaddr inport fwaddr fwport\n");
		exit (1);
	}
	if (carrier == -1) {
		carrier = 't';
	} else if (carrier == 'x') {
		dtls = 1;
	} else if (carrier == 'y') {
		carrier = 'x';	// With dtls==0
	}
	if (cmdsoxpath) {
		if (tlspool_socket (cmdsoxpath) == -1) {
			perror ("Failed to open TLS Pool command socket");
			exit (1);
		}
	}
	tlsdata.flags = (dtls? PIOF_STARTTLS_DTLS: 0);
	if (role == 'c') {
		tlsdata.flags |= PIOF_STARTTLS_SEND_SNI;
	}
	//
	// Parse addresses and ports in the remaining arguments
	if (inet_pton (AF_INET6, argv [optind + 0], &insa.sin6_addr) == 0) {
		fprintf (stderr, "Not an incoming IPv6 address: %s\n", argv [optind + 0]);
		exit (1);
	}
	if (inet_pton (AF_INET6, argv [optind + 2], &fwsa.sin6_addr) == 0) {
		fprintf (stderr, "Not a forwarding IPv6 address: %s\n", argv [optind + 2]);
		exit (1);
	}
	insa.sin6_port = htons (str2port (argv [optind + 1]));
	fwsa.sin6_port = htons (str2port (argv [optind + 3]));
	//
	// Listen to the incoming address
	switch (carrier) {
	case 't':
		tlsdata.ipproto = IPPROTO_TCP;
		sox = socket (AF_INET6, SOCK_STREAM, 0);
		break;
	case 'u':
		tlsdata.ipproto = IPPROTO_UDP;
		sox = socket (AF_INET6, SOCK_DGRAM, 0);
		break;
	case 'x':
		tlsdata.ipproto = IPPROTO_SCTP;
		tlsdata.streamid = stream;
		sox = socket (AF_INET6, SOCK_SEQPACKET, 0);
		break;
	}
	if (sox == -1) {
		perror ("Failed to open socket");
		exit (1);
	}
	if (bind (sox, (struct sockaddr *) &insa, sizeof (insa)) == -1) {
		perror ("Failed to bind socket to inaddr:inport");
		exit (1);
	}
	if (listen (sox, 5) == -1) {
		perror ("Failed to listen to socket");
		exit (1);
	}
	//
	// Fork off a daemon process
	switch (fork ()) {
	case -1:
		perror ("Failed to fork background daemon");
		exit (1);
	case 0:
		if (setsid () == (pid_t) -1) {
			perror ("Failed to create background session");
			exit (1);
		}
		break;
	default:
		printf ("DEBUG: Forked daemon process to the background\n");
		exit (0);
	}
	//
	// Handle incoming connections
	while (1) {
		int cnx;
		int fwd;
		struct copydata *sub;
		starttls_t curtlsdata;
		memcpy (&curtlsdata, &tlsdata, sizeof (curtlsdata));
		cnx = accept (sox, NULL, 0);
		if (cnx == -1) {
			perror ("Failed to accept incoming connection");
			continue;
		}
		if (role == 's') {
			cnx = starttls_server (cnx, &curtlsdata, NULL);
			if (cnx == -1) {
				perror ("Failed to setup TLS server");
				continue;
			}
		}
		switch (carrier) {
		case 't':
			fwd = socket (AF_INET6, SOCK_STREAM, 0);
			break;
		case 'u':
			fwd = socket (AF_INET6, SOCK_DGRAM, 0);
			break;
		case 'x':
			fwd = socket (AF_INET6, SOCK_SEQPACKET, 0);
			break;
		}
		if (fwd == -1) {
			perror ("Failed to create forwarding socket");
			exit (1);
		}
		if (connect (fwd, (struct sockaddr *) &fwsa, sizeof (fwsa)) == -1) {
			perror ("Failed to forward connection");
			close (fwd);
			close (cnx);
			continue;
		}
		if (role == 'c') {
			fwd = starttls_client (fwd, &curtlsdata);
			if (fwd == -1) {
				perror ("Failed to setup TLS client");
				close (cnx);
				close (fwd);
				continue;
			}
		}
		if (!(sub = (struct copydata *) malloc (sizeof (struct copydata)))) {
			perror ("Failed to allocate thread data");
			exit (1);
		}
		sub->cnx = cnx;
		sub->fwd = fwd;
		errno = pthread_create (&sub->thread, NULL, copycat, (void *) sub);
		if (errno) {
			perror ("Failed to start copycat thread");
			close (cnx);
			close (fwd);
			free (sub);
		}
	}
	exit (1);
}

