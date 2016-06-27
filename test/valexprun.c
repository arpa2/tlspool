/* valexpsimp.c -- work out validation expressions and print the result
 *
 * This is a test program for the mapping of validation expressions.
 * It has no use for end users but all the more for correctness testing.
 *
 * From: Rick van Rein <rick@openfortress.nl>
 */


/********** VALIDATION EXPRESSION TEST RUNS **********
 * 
 * Consider the following output form a test file that
 * has as its first line the expression "ac|d&" and later
 * the signal vector "dca".  The test files in test-valexp-in
 * can apply any number of signal vectors to the expression
 * in the first line, and the output files contain multiple
 * fragments like the one quoted and explained below.
 *
 * The expression is parsed and simplied into a standard
 * form: operators from the outside to the inside are
 * | & and optional ~.  The pretty printer below prints
 * an & combination of symbols a and inverses ~a in one
 * form, with the ~ after positive and before negative
 * tests.
 *
 * The signal vectors provide outputs from individual
 * tests, and these will be provided one by one to the
 * validation expression, which will be updated accordingly.
 * As soon as possible, the final result from the validation
 * expression is reported back, even when events may still
 * be flowing in, even after their handlers have been
 * stopped.  The formal end of such indicators is when the
 * validation expression as a whole is unregistered, which
 * happens at the end.  Every time a '~' is inserted, the
 * signal toggles between positive and negative.  It starts
 * positive.  Note that the string "~" can be used to write
 * a no-action signal vector, which just shows the innate
 * optimisation.
 *
 * Unknown or already processed or out-optimised symbols
 * are silently ignored.  For details see the exported
 * three functions from this module at the low end of this
 * source file.  At the end of processing, any unreported
 * symbols are considered false, regardless of their
 * desire to receive a positive or negative result.  This
 * roughly comes down to timeout processing.
 *
 * To explain the processing, let's consider this one:
 * 
 * SIGNAL VECTOR: "dca"
 * Input:  "ac|d&"
 *		The expression "ac|d&" will be parsed
 *		and below the signals d, c and a will
 *		be sent, all with the value True (no ~)
 *
 * Starting handler for 'a'
 * Starting handler for 'd'
 * Starting handler for 'c'
 *		The symbols that are required are
 *		started.  When a final result is already
 *		known at this point, this is not even done.
 *
 * Parsed value: "dc | ad"
 *		We have the output from the optimiser,
 *		and see two cases, each of which leads to
 *		immediate positive result when it individually
 *		evaluates to true.  The number of cases may be
 *		pruned when cases turn out to be impossible
 *
 * Setting predicate 'd' to True
 *		We send our first signal.
 *
 * Stopping handler for 'd'
 *		Since this is not an unknown anymore, the
 *		handler for d is stopped.  Every handler that
 *		was started will be stopped precisely once.
 *
 * Interm value: "c | a"
 *		The result after applying the new knowledge is
 *		a simpler form.  We can already predict what will
 *		happen when we next supply signal c.
 *
 * Setting predicate 'c' to True
 *		And of course we do.  Note how complete certainty
 *		is now achieved, without knowing the value of a.
 *
 * Stopping handler for 'a' 
 * Stopping handler for 'c'
 *		Both handlers are stopped, as neither will be
 *		needed anymore.  Active background processes may
 *		still lead to delivery of missing signals, which
 *		is no problem until the unregistration of the
 *		validation expression.
 *
 * FINAL OUTCOME: VALIDATED 
 *		And we receive our definitive output, without
 *		further care for the value of signal a.
 *
 * Interm value: "1 | a"
 *		Note how lazy; the expression is not even simplified
 *		any more, there is no reason to cut off the case that
 *		was waiting for signal a.  Nobody minds, nobody cares.
 *
 * Setting predicate 'a' to True
 *		The delayed delivery of signal a, as announced to
 *		be acceptable.
 *
 * Interm value: "1 | a"
 *		No change; the signal handler for a was stopped and
 *		the expression therefore stopped taking this signal.
 *
 * Result value: "1 | a"
 *		We are done sending signals, and will now unregister
 *		the validation expression (after double checking that
 *		no background processes could deliver any more signals).
 *
 * Unregistered validation expression
 *		Not surprisingly, the validation expression agrees
 *		to its removal and deallocation.
 *
 * The output along these lines is automatically stored in the directory
 * data-valexp-out, where it is actually managed by GIT, so you can
 * easily do "git diff" on any set of files you like, and so you get
 * to see it while checking in other work.  The Makefile rebuilds these
 * files when the "all" target is built.  The Makefile also checks that
 * all files are part of GIT, as well as a balance in the number of
 * FINAL and SIGNAL lines, and a balance in the number of Starting and
 * Stopping lines.  It will stop hard when not.  This build target is
 * the last for the "all" target of the main project directory Makefile.
 *
 * As an example of how GIT is used: we fixed the lazy "1 | a" printing
 * so the pretty printer would only show "1" in such fully determined
 * cases.  We reran this program on the test data, and used "git diff ."
 * in data-valexp-out to find the following adaption to the foregoing
 * output:
 *    @@ -231,10 +231,10 @@ Setting predicate 'c' to True
 *     Stopping handler for 'a'
 *     Stopping handler for 'c'
 *     FINAL OUTCOME: VALIDATED
 *    -Interm value: "1 | a"
 *    +Interm value: "1"
 *     Setting predicate 'a' to True
 *    -Interm value: "1 | a"
 *    -Result value: "1 | a"
 *    +Interm value: "1"
 *    +Result value: "1"
 *     Unregistered validation expression
 *    
 * Clearly, this is helpful feedback; the logic still works as before.
 */


#include <stdlib.h>
#include <stdarg.h>

#include <ctype.h>


/* Brutally include the file being tested */
#include "../src/validate.c"


void *opaque_mydata = (void *) "tralala";



/* Functions handling callbacks */


void valexp_mystart (void *mydata, struct valexp *ve, char pred) {
	assert (mydata == opaque_mydata);
	printf ("Starting handler for '%c'\n", pred);
}

void valexp_mystop (void *mydata, struct valexp *ve, char pred) {
	assert (mydata == opaque_mydata);
	printf ("Stopping handler for '%c'\n", pred);
}

void valexp_myfinal (void *mydata, struct valexp *ve, bool value) {
	assert (mydata == opaque_mydata);
	printf ("FINAL OUTCOME: %s\n", value? "VALIDATED": "FAILED");
}


struct valexp_handling valexp_myfun = {
	.handler_stop  = valexp_mystop,
	.handler_start = valexp_mystart,
	.handler_final = valexp_myfinal,
};


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

void valexprun (const char *valexp, char *signals) {
	struct valexp *ve;
	char *inexpr [2];
	bool setvalue;
	inexpr [0] = strdup (valexp);
	inexpr [1] = NULL;
	printf ("Input:  \"%s\"\n", inexpr [0]);
	ve = valexp_register (inexpr, &valexp_myfun, opaque_mydata);
	free (inexpr [0]);
	if (ve == NULL) {
		fprintf (stderr, "Failed to parse validation expression \"%s\"\n", valexp);
		exit (1);
	}
	output_valexp ("Parsed value: \"%s\"\n", ve);
	setvalue = 1;
	while (*signals) {
		if (*signals == '~') {
			setvalue = !setvalue;
		} else {
			printf ("Setting predicate '%c' to %s\n", *signals, setvalue? "True": "False");
			valexp_setpredicate (ve, *signals, setvalue);
		}
		signals++;
		output_valexp ("Interm value: \"%s\"\n", ve);
	}
	output_valexp ("Result value: \"%s\"\n", ve);
	valexp_unregister (ve);
	printf ("Unregistered validation expression\n");
}


int main (int argc, char *argv []) {
	int i;
	char *inexpr;
	char *signals;
	int ok;
	//
	// Check arguments
	setup_validate ();
	ok = (argc >= 2);
	for (i=2; i<argc; i++) {
		signals = argv [i];
		while (VALEXP_CHARKNOWN (*signals) || (*signals == '~')) {
			signals++;
		}
		ok = ok && (*signals == '\0');
	}
	if (!ok) {
		fprintf (stderr, "Usage: %s valexp [signals...]\nwhere the optional signals follow the pattern\n[%s]*(~[%s]*)?\n", argv [0], valexp_varchars, valexp_varchars);
		exit (1);
	}
	//
	// Process arguments
	inexpr = argv [1];
	printf ("VALIDATION EXPRESSION: \"%s\"\n", inexpr);
	for (i=2; i<argc; i++) {
		signals = argv [i];
		printf ("\nSIGNAL VECTOR: \"%s\"\n", signals);
		valexprun (inexpr, signals);
	}
	printf ("\nCOMPLETED %d TESTS ON \"%s\"\n", argc-2, inexpr);
	//
	// Return success
	cleanup_validate ();
	exit (0);
}
