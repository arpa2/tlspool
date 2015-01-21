/* tlspool/daemon.c -- Daemon setup code */

#include <stdlib.h>
#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <string.h>



void process_hangup (int hangupsignal) {
	fprintf (stderr, "DEBUG: Received signal %d as a hangup request\n");
	hangup_service ();
}


static struct sigaction hupaction = {
	.sa_handler = process_hangup,
};


int main (int argc, char *argv []) {
	char *cfgfile = NULL;
	char *pinentry = NULL;
	int parsing = 1;
	int kill_competition = 0;

	/*
	 * Cmdline argument parsing
	 */
	while (parsing) {
		int opt = getopt (argc, argv, "kc:p:P:");
		switch (opt) {
		case 'k':
			if (kill_competition) {
				fprintf (stderr, "You can only flag kill-the-competition once\n");
				exit (1);
			}
			kill_competition = 1;
			break;
		case 'c':
			if (cfgfile) {
				fprintf (stderr, "You can only specify one config file\n");
				exit (1);
			}
			cfgfile = strdup (optarg);
			break;
		case 'p':
			if (pinentry) {
				fprintf (stderr, "You can only specify one pinentry socket file\n");
				exit (1);
			}
			pinentry = strdup (optarg);
			break;
		case -1:
			parsing = 0;
			break;
		}
	}
	if (cfgfile && pinentry) {
		fprintf (stderr, "You should specify either a pinentry socket file or a config file\n");
		free (cfgfile);
		exit (1);
	}
	if (kill_competition && pinentry) {
		fprintf (stderr, "You cannot combine kill-the-competition with client options\n");
		exit (1);
	}
	if (!cfgfile) {
		cfgfile = strdup ("/etc/tlspool.conf");
	}

	//TODO// setup syslogging

	/*
	 * Mode selection: Daemon or PIN entry
	 */
	if (pinentry) {
		enter_pins (pinentry);
	} else {
		int pid = fork ();
		switch (pid) {
		case -1:
			perror ("Failed to fork daemon");
			exit (1);
		case 0:
			setsid ();
			if (sigaction (SIGHUP, &hupaction, NULL) != 0) {
				perror ("Failed to setup HUP signal handler");
			}
			//TODO// close the common fd's 0/1/2
			setup_handler ();
			setup_pinentry ();
			parse_cfgfile (cfgfile, kill_competition);
			run_service ();
			fprintf (stderr, "DEBUG: Cleanup started\n");
			cleanup_pinentry ();
			cleanup_handler ();
			fprintf (stderr, "DEBUG: Orderly shutdown seems to have worked\n");
			break;
		default:
			fprintf (stderr, "Started tlspool daemon on PID %d\n", pid);
			break;
		}
	}

	/*
	 * Done.  Exit, closing all resources in the parent.
	 */
	free (cfgfile);
	return 0;
}

