/* Configuration file parsing.  This is compiled as a separate binary object, to
 * permit linking it in only when needed.
 *
 * From: Rick van Rein <rick@openfortress.nl>
 */


#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <ctype.h>

#include <tlspool/starttls.h>


/* Fetch a configuration variable value from the configuration file.  This is not
 * an efficient procedure, at best suited for startup of tools or daemons; it
 * will iterate over the config file until it reads the desired value.  The value
 * returned is allocated and should be freed by the caller using free().
 *
 * When cfgfile is NULL, the environment variable TLSPOOL_CONFIGFILE is
 * tried first, followed by the default setting from the macro 
 * TLSPOOL_DEFAULT_CONFIG_PATH as defined in <tlspool/starttls.h>.
 *
 * The value returned is NULL when the variable is not found, including when this
 * is due to errors such as not being able to open the file.
 */
char *tlspool_configvar (char *cfgfile, char *varname) {
	FILE *cf;
	char line [514];
	int linelen;
	int eof = 0;
	char *here;
	struct cfgopt *curopt;
	int found;
	char *retval = NULL;

	if (cfgfile == NULL) {
		cfgfile = getenv ("TLSPOOL_CFGFILE");
	}
	if (cfgfile == NULL) {
		cfgfile = TLSPOOL_DEFAULT_CONFIG_PATH;
	}

	assert (cfgfile != NULL);
	assert (varname != NULL);

	cf = fopen (cfgfile, "r");
	if (cf == NULL) {
		perror ("Failed to open configuration file");
		goto cleanup;
	}

	while (!eof) {
		if (!fgets (line, sizeof (line)-1, cf)) {
			if (feof (cf)) {
				eof = 1;
				continue;
			} else {
				perror ("Error while reading configuration file");
				exit (1);
			}
		}
		linelen = strlen (line);
		if (linelen == 0) {
			eof = 1;
			continue;
		}
		if (line [linelen-1] == (char) EOF) {
			linelen--;
			eof = 1;
		}
		if (line [linelen-1] != '\n') {
			fprintf (stderr, "Configuration line too long\n");
			goto cleanup;
		}
		line [--linelen] = 0;
		if (linelen == 0) {
			continue;
		}
		if (line [0] == '#') {
			continue;
		}
		here = line;
		while ((*here) && isspace (*here)) {
			here++;
		}
		if (!*here) {
			continue;
		}
		if (here != line) {
			fprintf (stderr, "Configuration line starts with whitespace:\n%s\n", line);
			goto cleanup;
		}
		while ((*here) && (*here != ' ')) {
			here++;
		}
		if (!*here) {
			fprintf (stderr, "Configuration line misses space after keyword:\n%s\n", line);
			goto cleanup;
		}
		*here++ = '\0';
		if (strcmp (varname, line) == 0) {
			// Success!  We set the return value and end the loop
			retval = strdup (here);
			goto cleanup;
		}
	}

cleanup:
	if (cf != NULL) {
		fclose (cf);
		cf = NULL;
	}
	return retval;
}

