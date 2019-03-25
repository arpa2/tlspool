/* error.c -- Map error codes between the various error subsystems.
 *
 * From: Rick van Rein <rick@openfortress.nl>
 */

#include "whoami.h"

#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>

#include <syslog.h>

#include <errno.h>
#include <com_err.h>
#include <errortable.h>

#include <db.h>

#include <tlspool/internal.h>


/* Data structures for logging configuration */

static unsigned int log_filter;

static pthread_key_t varkey_errstr;


/* Fetch the thread-specific string variable paired to errno */
char *error_getstring (void) {
	char *errstr;
	return (char *) pthread_getspecific (varkey_errstr);
}

/* Set the thread-specific string variable paired to errno */
void error_setstring (char *errstr) {
	pthread_setspecific (varkey_errstr, (void *) errstr);
}

/* Setup logging structures for error reporting.
 */
void setup_error (void) {
	unsigned int log_perror;
	unsigned int log_level;
	log_perror = cfg_log_perror ();
	log_level = cfg_log_level ();
	log_filter = cfg_log_filter ();
	openlog ("TLS Pool", LOG_CONS | LOG_PID | log_perror, log_level);
	if (pthread_key_create (&varkey_errstr, NULL) != 0) {
		errno = ENOMEM;
		error_setstring ("Unable to allocate pthread key resource");
		exit (1);
	}
}

void cleanup_error (void) {
	closelog ();
}


/* Forward a message to syslog, assuming that the configuration wants it */

void tlog (unsigned int logmask, int priority, char *format, ...) {
	va_list varg;
	va_start (varg, format);
	if ((logmask & log_filter) != 0) {
		vsyslog (priority, format, varg);
	}
	va_end (varg);
}



/* Mapping for error codes between the various subsystems in use. */

void error_posix2strings (char *new_errstr) {
	char *errstr;
	//
	// Sanity checks
	if (errno == 0) {
		return;
	}
	errstr = error_getstring ();
	if (errstr != NULL) {
		return;
	}
	//
	// Report strings
	if (new_errstr == NULL) {
		new_errstr = "Unspecified POSIX error";
	}
	error_setstring (new_errstr);
}

void error_db2comerr (int db_errno, char *new_errstr) {
	char *errstr;
	//
	// Sanity checks
	if (db_errno == 0) {
		return;
	}
	errstr = error_getstring ();
	if (errstr != NULL) {
		return;
	}
	//
	// Report the descriptive error
	if (new_errstr == NULL) {
		new_errstr = db_strerror (db_errno);
	}
	if (new_errstr == NULL) {
		new_errstr = "Undescribed database failure";
	}
	tlog (TLOG_DB, LOG_ERR, "DB error: %s", new_errstr);
	error_setstring (new_errstr);
	//
	// Translate error to a POSIX errno value
	// See <tlspool/commands.h> above PIOC_ERROR_V2
	errno = db_errno;
}

