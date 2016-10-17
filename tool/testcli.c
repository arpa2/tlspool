/* tlspool/testcli.c -- Exchange plaintext stdio over the network */

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


static starttls_t tlsdata_cli = {
	.flags =  PIOF_STARTTLS_LOCALROLE_CLIENT
		| PIOF_STARTTLS_REMOTEROLE_SERVER,
	.local = 0,
	.ipproto = IPPROTO_TCP,
	.localid = "testcli@tlspool.arpa2.lab",
	.remoteid = "testsrv@tlspool.arpa2.lab",
	.service = "generic",
};

void sigcont_handler (int signum);
static struct sigaction sigcont_action = {
	.sa_handler = sigcont_handler,
	.sa_mask = 0,
	.sa_flags = SA_NODEFER
};

static int sigcont = 0;

void runterminal (int chanio) {
	struct pollfd inout [2];
	ssize_t sz;
	char buf [512];
	inout [0].fd = 0;
	inout [1].fd = chanio;
	inout [0].events = inout [1].events = POLLIN;
	while (1) {
		if (sigcont) {
			sigcont = 0;
			printf ("Received SIGCONT, will now initiate TLS handshake renegotiation\n");
			tlsdata_cli.flags =  PIOF_STARTTLS_LOCALROLE_CLIENT
					| PIOF_STARTTLS_REMOTEROLE_SERVER
					| PIOF_STARTTLS_RENEGOTIATE;
			strcpy (tlsdata_cli.localid, "testcli@tlspool.arpa2.lab");
			strcpy (tlsdata_cli.remoteid, "testsrv@tlspool.arpa2.lab");
			if (-1 == tlspool_starttls (-1, &tlsdata_cli, NULL, NULL)) {
				printf ("TLS handshake renegotiation failed, terminating\n");
				break;
			}
			printf ("TLS handshake renegotiation completed successfully\n");
		}
		if (poll (inout, 2, -1) == -1) {
			if (sigcont) {
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
			printf ("Read %d bytes, sigcont==%d (should be 0 for proper operation)\n", sz, sigcont);
			if (sz == -1) {
				break;
			} else if (sz == 0) {
				errno = 0;
				break;
			} else if (send (chanio, buf, sz, MSG_DONTWAIT) != sz) {
				break;
			} else {
				printf ("Sent %d bytes\n", sz);
			}
		}
		if (inout [1].revents & POLLIN) {
			sz = recv (chanio, buf, sizeof (buf), MSG_DONTWAIT);
			printf ("Received %d bytes, sigcont==%d (should be 0 for proper operation)\n", sz, sigcont);
			if (sz == -1) {
				break;
			} else if (sz == 0) {
				errno = 0;
				break;
			} else if (write (1, buf, sz) != sz) {
				break;
			} else {
				printf ("Printed %d bytes\n", sz);
			}
		}
	}
}


void sigcont_handler (int signum) {
	sigcont = 1;
}


int main (int argc, char *argv) {
	int plainfd;
	int sox;
	struct sockaddr_in6 sin6;
	sigset_t sigcontset;
	uint8_t rndbuf [16];

	if (sigemptyset (&sigcontset) ||
	    sigaddset (&sigcontset, SIGCONT) ||
	    pthread_sigmask (SIG_BLOCK, &sigcontset, NULL)) {
		perror ("Failed to block SIGCONT in worker threads");
		exit (1);
	}

reconnect:
	sox = socket (AF_INET6, SOCK_STREAM, 0);
	if (sox == -1) {
		perror ("Failed to create socket on testcli");
		exit (1);
	}
	memset (&sin6, 0, sizeof (sin6));
	sin6.sin6_family = AF_INET6;
	sin6.sin6_port = htons (12345);
	memcpy (&sin6.sin6_addr, &in6addr_loopback, 16);
	if (connect (sox, (struct sockaddr *) &sin6, sizeof (sin6)) == -1) {
		perror ("Socket failed to connect on testcli");
		if (errno == ECONNREFUSED) {
			close (sox);
			sleep (1);
			goto reconnect;
		}
		exit (1);
	}
	plainfd = -1;
	if (-1 == tlspool_starttls (sox, &tlsdata_cli, &plainfd, NULL)) {
		perror ("Failed to STARTTLS on testcli");
		if (plainfd >= 0) {
			close (plainfd);
		}
		exit (1);
	}
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
	if (tlspool_prng ("EXPERIMENTAL-tlspool-test", NULL, 16, rndbuf, tlsdata_cli.ctlkey) == -1) {
		printf ("ERROR: Could not extract data with PRNG function\n");
	} else {
		printf ("PRNG bytes: %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\n",
			rndbuf [ 0], rndbuf [ 1], rndbuf [ 2], rndbuf [ 3],
			rndbuf [ 4], rndbuf [ 5], rndbuf [ 6], rndbuf [ 7],
			rndbuf [ 8], rndbuf [ 9], rndbuf [10], rndbuf [11],
			rndbuf [12], rndbuf [13], rndbuf [14], rndbuf [15]);
	}
	printf ("DEBUG: STARTTLS succeeded on testcli\n");
	if (-1 == sigaction (SIGCONT, &sigcont_action, NULL)) {
		perror ("Failed to install signal handler for SIGCONT");
		close (plainfd);
		exit (1);
	} else if (pthread_sigmask (SIG_UNBLOCK, &sigcontset, NULL)) {
		perror ("Failed to unblock SIGCONT on terminal handler");
		close (plainfd);
		exit (1);
	} else {
		printf ("SIGCONT will trigger renegotiation of the TLS handshake\n");
	}
	printf ("DEBUG: Local plainfd = %d\n", plainfd);
	runterminal (plainfd);
	close (plainfd);
	printf ("DEBUG: Closed connection.  Waiting 2s to improve testing.\n");
	sleep (2);
	return 0;
}

