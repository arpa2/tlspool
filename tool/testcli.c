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
#include <arpa/inet.h>

#include <tlspool/starttls.h>

#include "socket.h"
#include "chat_builtin.h"
#include "runterminal.h"

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


void sigcont_handler (int signum) {
	sigcont = 1;
}


int exit_val = 1;
void graceful_exit (int signum) {
	exit (exit_val);
}


int main (int argc, char **argv) {
	int plainfd;
	int sox;
	struct sockaddr_storage sa;
	sigset_t sigcontset;
	uint8_t rndbuf [16];
	bool do_signum = false;
	bool do_timeout = false;
	int signum = -1;
	int timeout = -1;
	bool do_chat = false;
	int    chat_argc = 0;
	char **chat_argv = NULL;
	char *progname = NULL;

	// argv[1] is SNI or . for none;
	// argv[2] is address and requires argv[3] for port
	if ((argc == 1) || (argc == 3)) {
		fprintf (stderr, "Usage: %s servername|. [address port [0|signum|-timeout [chatargs...]]]\n", argv [0]);
		exit (1);
	}

	// store the program name
	/* progname = strrchr (argv [0], '/'); */
	if (progname == NULL) {
		progname = argv [0];
	}

	// process argv[1] with SNI or its overriding "."
	if (strcmp (argv [1], ".") != 0) {
		if (strlen (argv [1]) > sizeof (tlsdata_cli.remoteid) - 1) {
			fprintf (stderr, "Server name exceeded %d characters\n",
					sizeof (tlsdata_cli.remoteid) - 1);
			exit (1);
		}
		strcpy (tlsdata_cli.remoteid, argv [1]);
	}

	// process optional argv[2,3] with address and port
	memset (&sa, 0, sizeof (sa));
	char *addrstr = "::1", *portstr = "12345";
	if (argc >= 4) {
		addrstr = argv [2];
		portstr = argv [3];
	}
	if (!socket_parse (addrstr, portstr, (struct sockaddr *) &sa)) {
		fprintf (stderr, "Incorrect address %s and/or port %s\n", argv [2], argv [3]);
		exit (1);
	}

	// process optional 0|-signum|timeout
	// where 0 means nothing, -signum awaits the signal number, timeout is seconds to finish
	if (argc >= 5) {
		int parsed = atoi (argv [4]);
		if (parsed < 0) {
			do_timeout = true;
			timeout = -parsed;
		} else if (parsed > 0) {
			do_signum = true;
			signum = parsed;
		}
	}

	// process optional argv[5+] with chat information
	if (argc > 5) {
		do_chat = true;
		chat_argc = argc - 5;
		chat_argv = argv + 5;
	}

	if (sigemptyset (&sigcontset) ||
	    sigaddset (&sigcontset, SIGCONT) ||
	    pthread_sigmask (SIG_BLOCK, &sigcontset, NULL)) {
		perror ("Failed to block SIGCONT in worker threads");
		exit (1);
	}

	// When timeout hits, we should stop gracefully, with exit(exit_val)
	if (do_timeout) {
		if (signal (SIGALRM, graceful_exit) == SIG_ERR) {
			fprintf (stderr, "Failed to install signal handler for timeout\n");
			exit (1);
		}
		alarm (timeout);
		printf ("Scheduled to exit(exit_val) in %d seconds\n", timeout);
	}

	// When the signal hits, we should stop gracefully, with exit(exit_val)
	if (do_signum) {
		if (signal (signum, graceful_exit) == SIG_ERR) {
			fprintf (stderr, "Failed to install signal handler for signal %d\n", signum);
			exit (1);
		}
		printf ("Scheduled to exit(exit_val) upon reception of signal %d\n", signum);
	}

reconnect:
	if (!socket_client ((struct sockaddr *) &sa, SOCK_STREAM, &sox)) {
		perror ("Failed to create socket on testcli");
		exit (1);
	}
	exit_val = 1;
	printf ("--\n");
	fflush (stdout);
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
	if (do_chat) {
		if (chat_builtin (plainfd, progname, chat_argc, chat_argv) != 0) {
			fprintf (stderr, "Chat session failed on the client side\n");
			exit (1);
		}
	} else {
		runterminal (plainfd, &sigcont, &tlsdata_cli,
			PIOF_STARTTLS_LOCALROLE_CLIENT | PIOF_STARTTLS_REMOTEROLE_SERVER | PIOF_STARTTLS_RENEGOTIATE,
			"testcli@tlspool.arpa2.lab",
			"testsrv@tlspool.arpa2.lab"
		);
	}
	close (plainfd);
	exit_val = 0;
	printf ("DEBUG: Closed connection.  Waiting 2s to improve testing.\n");
	sleep (2);
	return 0;
}

