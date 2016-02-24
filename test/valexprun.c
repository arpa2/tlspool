/* valexpsimp.c -- work out validation expressions and print the result
 *
 * This is a test program for the mapping of validation expressions.
 * It has no use for end users but all the more for correctness testing.
 *
 * From: Rick van Rein <rick@openfortress.nl>
 */


#include <stdlib.h>
#include <stdarg.h>

#include <ctype.h>


/* Brutally include the file being tested */
#include "../src/validate.c"


/* Add logging routine assumed by validate.c */
void tlog (unsigned int ign_logmask, int ign_priority, char *format, ...) {
	va_list varg;
	va_start (varg, format);
	vprintf (format, varg);
	printf ("\n");
	va_end (varg);
}


void output_valexp (char *fmt, struct valexp *ve) {
	char outbuf [1024];
	snprint_valexp (outbuf, sizeof (outbuf), ve);
	printf (fmt, outbuf);
}

int main (int argc, char *argv []) {
	int i;
	char *inexpr [2];
	char *action;
	int ok;
	struct valexp *ve;
	//
	// Check arguments
	setup_validate ();
	ok = (argc >= 2);
	for (i=2; i<argc; i++) {
		action = argv [i];
		while (VALEXP_CHARKNOWN (*action)) {
			action++;
		}
		if (*action == '~') {
			action++;
			while (VALEXP_CHARKNOWN (*action)) {
				action++;
			}
		}
		ok = ok && (*action == '\0');
	}
	if (!ok) {
		fprintf (stderr, "Usage: %s valexp [action...]\nwhere the optional actions follow the pattern\n[%s]*(~[%s]*)?\n", argv [0], valexpvarchars, valexpvarchars);
		exit (1);
	}
	//
	// Process arguments
	inexpr [0] = strdup (argv [1]);
	inexpr [1] = NULL;
	for (i=0; i<1; i++) {
		printf ("Input:  \"%s\"\n", inexpr [i]);
	}
	ve = construct_valexp (inexpr);
	if (ve == NULL) {
		fprintf (stderr, "Failed to parse validation expression \"%s\"\n", argv [1]);
		exit (1);
	}
	output_valexp ("Allocd: \"%s\"\n", ve);
	expand_cases (inexpr [0], ve);
	output_valexp ("Parsed: \"%s\"\n", ve);
	free (inexpr [0]);
	for (i=2; i<argc; i++) {
		action = argv [i];
		printf ("Action: \"%s\"\n", action);
		printf ("TOD:    Action processing not yet implemented\n");
		//TODO// process_action (action);
		output_valexp ("Output: \"%s\"\n", ve);
	}
	//
	// Return success
	cleanup_validate ();
	exit (0);
}
