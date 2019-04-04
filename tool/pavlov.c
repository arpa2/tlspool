/* pavlov.c -- Simple wrapper program around libpavlov.
 *
 * This is a substitute for chat(8) functionality for expect/response
 * interactions, founded on extended regular expressions (after ?) and
 * string printing (after !).
 *
 * These functions are (also) used in the TLS Tunnel, testcli, testsrv,
 * testpeer programs.
 *
 * From: Rick van Rein <rick@openfortress.nl>
 */


#include <stdlib.h>

#include <errno.h>
#include <com_err.h>

#include <arpa2/pavlov.h>


int main (int argc, char *argv []) {
	char *progname = argv [0];
	argc--;
	argv++;
	if (pavlov (0, 1, progname, argc, argv)) {
		com_err (progname, errno, "Error in pavlov");
		exit (1);
	} else {
		exit (0);
	}
}
