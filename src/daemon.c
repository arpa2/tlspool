/* tlspool/daemon.c -- Daemon setup code */

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>


int main (int argc, char *argv []) {
	char *pinentry = NULL;
	char *cfgfile = NULL;
	int parsing = 1;

	/*
	 * Cmdline argument parsing
	 */
	while (parsing) {
		int opt = getopt (argc, argv, "p:c:");
		switch (opt) {
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
		exit (1);
	}
	if (!cfgfile) {
		cfgfile = "/etc/tlspool.conf";
	}

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
			parse_cfgfile (cfgfile);
			run_service ();
			break;
		default:
			fprintf (stderr, "Started tlspool daemon on PID %d\n", pid);
			break;
		}
	}

	/*
	 * Done.  Exit, closing all resources in the parent.
	 */
	return 0;
}

