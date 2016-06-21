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

#include <unistd.h>


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

void showstatus (char *title) {
	printf ("\n\n\n# %s\n", title);
	printf ("\n\n\n## Disclosure database\n\n\n");
	testcmd ("../tool/get_disclose "CONFFILE" "REMOTEID);
	testcmd ("../tool/get_disclose "CONFFILE" "REMOTEID_PATN);
	testcmd ("../tool/get_disclose "CONFFILE" "LOCALID);
	printf ("\n\n\n## LocalID database\n\n\n");
	testcmd ("../tool/get_localid "CONFFILE" "REMOTEID" X.509,client,server");
	testcmd ("../tool/get_localid "CONFFILE" "LOCALID" X.509,client,server");
	testcmd ("../tool/get_localid "CONFFILE" "REMOTEID" OpenPGP,client,server");
	testcmd ("../tool/get_localid "CONFFILE" "LOCALID" OpenPGP,client,server");
	printf ("\n\n\n## Trust database\n\n\n");
	testcmd ("../tool/get_trust "CONFFILE" x509,client,server "ANCHOR_HEX);
	testcmd ("../tool/get_trust "CONFFILE" x509,client,server "ANCHOR_HEX);
	testcmd ("../tool/get_trust "CONFFILE" pgp,client,server "ANCHOR_HEX);
	testcmd ("../tool/get_trust "CONFFILE" pgp,client,server "ANCHOR_HEX);
	printf ("\nThat was our last test for %s\n\n\n", title);
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
	pulleyback_close (backend);
}


char *test0 [] = { "config=../etc/tlspool.conf", "type=disclose", "args=localid,remoteid", NULL };
char *test1 [] = { "config=../etc/tlspool.conf", "type=disclose", "args=remoteid,localid", NULL };
char *test2 [] = { "config=../etc/tlspool.conf", "type=localid", "args=pkcs11,cred", "subtype=x509,client", NULL };

char **tests [] = { test0, test1, test2, NULL };


int main (int argc, char *argv []) {
	char ***testp;
	void *backend;
	int testnr = 0;
	char testtitle [105];
	close (2);
	dup2 (1, 2);
	showstatus ("Initial status");
	for (testp = tests; *testp != NULL; testp++) {
		backend = open_backend (*testp);
		if (backend == NULL) {
			continue;
		}
		snprintf (testtitle, 100, "Test number %d\n", testnr++);
		showstatus (testtitle);
		close_backend (backend);
	}
	showstatus ("Final status");
	exit (0);
}
