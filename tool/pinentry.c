/* pinentry.c -- User space program for entering PINs for the TLS Pool.
 *
 * From: Rick van Rein <rick@openfortress.nl>
 */


#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <unistd.h>
#include <syslog.h>

#include <tlspool/commands.h>
#include <tlspool/starttls.h>


void pincb (pinentry_t *entry, void *null_data) {
	char *pwd;
	printf ("\n***** PIN ENTRY REQUEST FROM THE TLS POOL *****\n"
		"Token Manuf: %s\n"
		"      Model: %s\n"
		"     Serial: %s\n"
		"      Label: %s\n"
		"    Attempt: %d\n",
		entry->token_manuf,
		entry->token_model,
		entry->token_serial,
		entry->token_label,
		entry->attempt);
	pwd = getpass (entry->prompt);
	memset (entry->pin, 0, sizeof (entry->pin));
	if (pwd) {
		if (strlen (pwd) + 1 > sizeof (entry->pin)) {
			fprintf (stderr, "No support for PIN lenghts over 128\n");
		} else {
			strcpy (entry->pin, pwd);
		}
		memset (pwd, 0, strlen (pwd));
	}
}


int main (int argc, char *argv []) {
	int exitval;
	uint32_t regflags = 0;
	uint32_t responsetime_usec = 60 * 1000 * 1000;

	if (argc > 1) {
		fprintf (stderr, "Ignoring program arguments\n");
	}

	//
	// Open log, and also dump on stderr
	openlog ("pinentry", LOG_PID | LOG_PERROR | LOG_NDELAY, LOG_USER);

	//
	// Service the TLS Pool
	exitval = -tlspool_pin_service (NULL, regflags, responsetime_usec, pincb, NULL);
	if (exitval == 1) {
		perror ("pinentry service terminated");
	}

	//
	// Close the log facility
	closelog ();

	//
	// Return exitval
	return exitval;
}

