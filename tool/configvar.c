/* Simple front-end to the libtlspool_configvar call */


#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <tlspool/starttls.h>


int main (int argc, char *argv []) {
	char *cfgfile = NULL;
	int argi;
	int exitval = 0;
	if (argc < 2) {
		fprintf (stderr, "Usage: %s [-c tlspool.conf] configvar...\n");
		exit (1);
	} else if ((argc > 2) && (0 == strcmp (argv [1], "-c"))) {
		cfgfile = argv [2];
		argi = 3;
	} else {
		argi = 1;
	}
	while (argi < argc) {
		char *value = tlspool_configvar (cfgfile, argv [argi]);
		argi++;
		if (value == NULL) {
			fprintf (stderr, "Variable %s not found in %s\n",
				argv [argi],
				cfgfile ? cfgfile : "the configuration file");
			exitval = 1;
		} else {
			printf ("%s\n", value);
		}
	}
	exit (exitval);
}

