/* tlspool/daemon.c -- Daemon setup code */

#include <stdlib.h>
#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <string.h>

#include <syslog.h>

#include <tlspool/internal.h>

#include "manage.h"


void process_hangup (int hangupsignal) {
	tlog (TLOG_DAEMON, LOG_NOTICE, "Received signal %d as a hangup request");
	hangup_service ();
}


#ifndef WINDOWS_PORT
static struct sigaction hupaction = {
	.sa_handler = process_hangup,
};
#endif

#ifdef WINDOWS_PORT
int setup_winsock(void)
{
    WORD wVersionRequested;
    WSADATA wsaData;
    int err;

/* Use the MAKEWORD(lowbyte, highbyte) macro declared in Windef.h */
    wVersionRequested = MAKEWORD(2, 2);

    err = WSAStartup(wVersionRequested, &wsaData);
    if (err != 0) {
        /* Tell the user that we could not find a usable */
        /* Winsock DLL.                                  */
        printf("WSAStartup failed with error: %d\n", err);
        return 1;
    }

/* Confirm that the WinSock DLL supports 2.2.*/
/* Note that if the DLL supports versions greater    */
/* than 2.2 in addition to 2.2, it will still return */
/* 2.2 in wVersion since that is the version we      */
/* requested.                                        */

    if (LOBYTE(wsaData.wVersion) != 2 || HIBYTE(wsaData.wVersion) != 2) {
        /* Tell the user that we could not find a usable */
        /* WinSock DLL.                                  */
        printf("Could not find a usable version of Winsock.dll\n");
        WSACleanup();
        return 1;
    }
    else {
        printf("The Winsock 2.2 dll was found okay\n");
	}
	return 0;
}
        
#endif

int main (int argc, char *argv []) {
	char *cfgfile = NULL;
	int parsing = 1;
	int kill_competition = 0;

	/*
	 * Cmdline argument parsing
	 */
	while (parsing) {
		int opt = getopt (argc, argv, "kc:");
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
		case -1:
			parsing = 0;
			break;
		}
	}
	if (!cfgfile) {
		cfgfile = strdup ("/etc/tlspool.conf");
	}

	//TODO// setup syslogging

	//UNDO// sigset_t sigblockmask;
#if defined(HAVE_SYSTEMD) || defined(WINDOWS_PORT)
	int pid = -2;	/* Skip setsid() but otherwise proceed */
#else
	int pid = fork ();
#endif
	switch (pid) {
	case -1:
		perror ("Failed to fork daemon");
		exit (1);
	case 0:
#ifndef WINDOWS_PORT
		// Detach from the startup session
		setsid ();
#endif
	case -2:
#ifdef WINDOWS_PORT
		setup_winsock();
#endif

#ifndef WINDOWS_PORT
		//TODO// close the common fd's 0/1/2
		// Setup a SIGHUP handler to gracefully stop service
		if (sigaction (SIGHUP, &hupaction, NULL) != 0) {
			perror ("Failed to setup HUP signal handler");
		}
		if (signal (SIGPIPE, SIG_IGN) == SIG_ERR) {
			perror ("Failed to protect daemon from SIGPIPE");
		}
#endif
		//UNDO// // Block SIGINT, which is used between copycat() threads
		//UNDO// sigemptyset (&sigblockmask);
		//UNDO// sigaddset (&sigblockmask, SIGINT);
		//UNDO// if (sigprocmask (SIG_BLOCK, &sigblockmask, NULL) != 0) {
		//UNDO// 	perror ("Failed to set signal mask");
		//UNDO// 	exit (1);
		//UNDO// }
		// Setup program structures
		parse_cfgfile (cfgfile, kill_competition);
		setup_error ();
		tlog (TLOG_DAEMON, LOG_INFO, "TLS Pool started");
		setup_management ();
		setup_service ();
		setup_starttls ();
		setup_pinentry ();
		setup_ctlkey ();
		setup_validate ();
		// Run the TLS Pool service's main routine
		run_service ();
		// Cleanup for shutdown of the TLS Pool
		tlog (TLOG_DAEMON, LOG_DEBUG, "Preparing to stop -- Cleanup started");
		cleanup_ctlkey ();
		cleanup_pinentry ();
		cleanup_starttls ();
		cleanup_service ();
		cleanup_management ();
		cleanup_error ();
		cleanup_validate ();
		tlog (TLOG_DAEMON, LOG_DEBUG, "Orderly shutdown seems to have worked");
		tlog (TLOG_DAEMON, LOG_INFO, "TLS Pool stopped");
		break;
	default:
		break;
	}

	/*
	 * Done.  Exit, closing all resources in the parent.
	 */
	free (cfgfile);
	return 0;
}
