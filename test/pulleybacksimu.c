/* pulleybacksimu.c -- Simulation of driving the Pulley backend to the TLS Pool
 *
 * This simulates a series of calls that the SteamWorks Pulley could do on
 * the backend in ../pulleyback/ -- it links against the library formed there,
 * and tests the output with the ../test/get_xxx routines.
 *
 * From: Rick van Rein <rick@openfortress.nl>
 */


#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <time.h>
#include <unistd.h>

#include <libgen.h>
#include <syslog.h>


#include "../pulleyback/api.h"


#define REMOTEID "remoteid@tlspool.arpa2.lab"
#define REMOTEID_PATN "remoteid@.arpa2.lab"
#define LOCALID  "localid@tlspool.arpa2.lab"

#define CONFFILE "../etc/tlspool.conf"

#define X509FILE "tlspool-test-client-cert.der"
#define PGPFILE "tlspool-test-client-pubkey.pgp"

#define ANCHOR_HEX "aabbccddeeff"
#define ANCHOR_BYTES 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff

void inline testcmd (char *cmd) {
	int exitval;
	printf ("shell$ %s\n", cmd);
	exitval = system (cmd);
	printf ("$? = %d\n\n", exitval);
}

//TODO// Calling these subcommands causes trouble with the shared environment
//TODO// Note that db_stat does not give that same trouble with -h / -d ?!?
void showstatus (char *title) {
	printf ("\n\n\n# %s\n", title);
	// testcmd ("db_stat -h ../testdata/tlspool.env -d ../disclose.db");
	// printf ("\n\n\n## Disclosure database\n\n\n");
	// testcmd ("../tool/get_disclose "CONFFILE" "REMOTEID" >/dev/null");
	// testcmd ("../tool/get_disclose "CONFFILE" "REMOTEID_PATN" >/dev/null");
	// testcmd ("../tool/get_disclose "CONFFILE" "LOCALID" >/dev/null");
	// printf ("\n\n\n## LocalID database\n\n\n");
	// testcmd ("../tool/get_localid "CONFFILE" "REMOTEID" X.509,client,server"" >/dev/null");
	// testcmd ("../tool/get_localid "CONFFILE" "LOCALID" X.509,client,server"" >/dev/null");
	// testcmd ("../tool/get_localid "CONFFILE" "REMOTEID" OpenPGP,client,server"" >/dev/null");
	// testcmd ("../tool/get_localid "CONFFILE" "LOCALID" OpenPGP,client,server"" >/dev/null");
	// printf ("\n\n\n## Trust database\n\n\n");
	// testcmd ("../tool/get_trust "CONFFILE" x509,client,server "ANCHOR_HEX" >/dev/null");
	// testcmd ("../tool/get_trust "CONFFILE" x509,client,server "ANCHOR_HEX" >/dev/null");
	// testcmd ("../tool/get_trust "CONFFILE" pgp,client,server "ANCHOR_HEX" >/dev/null");
	// testcmd ("../tool/get_trust "CONFFILE" pgp,client,server "ANCHOR_HEX" >/dev/null");
	// printf ("\nThat was our last test for %s\n\n\n", title);
}


void *open_backend (char *argv []) {
	int argc = 0;
	int varc = 0;
	char *argsp;
	void *backend;
	for (argc = 0; argv [argc] != NULL; argc++) {
		if (strncmp (argv [argc], "args=", 5) != 0) {
			continue;
		}
		for (argsp = argv [argc]; argsp != NULL; argsp = strchr (argsp + 1, ',')) {
			varc++;
		}
	}
	backend = pulleyback_open (argc, argv, varc);
	if (backend == NULL) {
		printf ("\n\nERROR: BACKEND DID NOT OPEN PROPERLY\n\n");
	}
	return backend;
}

void close_backend (void *backend) {
	struct pulleyback_tlspool *self = backend;
	if (backend != NULL) {
		pulleyback_close (backend);
	}
}


char *test0 [] = { "pulleyback_tlspool", "config=../etc/tlspool.conf", "type=disclose", "args=localid,remoteid", NULL };
char *test1 [] = { "pulleyback_tlspool", "config=../etc/tlspool.conf", "type=disclose", "args=remoteid,localid", NULL };
char *test2 [] = { "pulleyback_tlspool", "config=../etc/tlspool.conf", "type=localid", "args=localid,pkcs11,cred", "subtype=x509,client", NULL };

uint8_t *args0 [2] = { "\x0c\x1clocalid@pulleyback.arpa2.lab", "\x0c\x1dremoteid@pulleyback.arpa2.lab" };
uint8_t *args1 [2] = { "\x0c\x1dremoteid@pulleyback.arpa2.lab", "\x0c\x1clocalid@pulleyback.arpa2.lab" };
uint8_t *args2 [3] = { "\x0c\x1clocalid@pulleyback.arpa2.lab", "\x0c\x24pkcs11:manuf=OpenFortress;serial=123", "\x0c\x1a-----LIKE A PGP KEY-----\r\n" };

char **tests [] = { test0, test1, test2, NULL };
uint8_t **argss [] = { args0, args1, args2, NULL };


int main (int argc, char *argv []) {
	char ***testp;
	uint8_t ***argsp;
	uint8_t derargs [3] [130];
	void *backend;
	int testnr = 0;
	char testtitle [105];
	close (2);
	dup2 (1, 2);
	openlog (basename (argv [0]), LOG_PERROR, LOG_LOCAL0);
	// showstatus ("Initial status");
	for (testp = tests, argsp = argss; *testp != NULL; testp++, argsp++) {
		backend = open_backend (*testp);
		if (backend == NULL) {
			continue;
		}
		snprintf (testtitle, 100, "Test number %d\n", testnr);
		showstatus (testtitle);
		pulleyback_add (backend, *argsp);
		if (pulleyback_commit (backend)) {
			printf ("Go have a look...\n");
		} else {
			printf ("Failed, so you probably won't find it...\n");
		}
		sleep (10);
		snprintf (testtitle, 100, "Added in test number %d\n", testnr++);
		showstatus (testtitle);
		pulleyback_del (backend, *argsp);
		if (pulleyback_commit (backend)) {
			printf ("It should be gone...\n");
		} else {
			printf ("Failed, so it is probably still there...\n");
		}
		close_backend (backend);
	}
	// showstatus ("Final status");
	closelog ();
	exit (0);
}
