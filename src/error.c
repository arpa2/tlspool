/* error.c -- Map error codes between the various error subsystems.
 *
 * From: Rick van Rein <rick@openfortress.nl>
 */


#include <config.h>

#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>

#include <syslog.h>
#include <errno.h>

#include <db.h>

#include <tlspool/internal.h>


#ifndef ENOKEY
#define ENOKEY ENOENT
#endif

#ifndef EREMOTEIO
#define EREMOTEIO EIO
#endif

#ifndef ENODATA
#define ENODATA ENOENT
#endif

#ifndef ENOTRECOVERABLE
#define ENOTRECOVERABLE EIO
#endif


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
		errno = EBADSLT;
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

void error_db2posix (int db_errno, char *new_errstr) {
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
		new_errstr = "Undescribed database failure";
	}
	tlog (TLOG_DB, LOG_ERR, "DB error: %s", new_errstr);
	error_setstring (new_errstr);
	//
	// Translate error to a POSIX errno value
	if (db_errno > 0) {
		errno = db_errno;
		return;
	}
	switch (db_errno) {
	case DB_BUFFER_SMALL:
	case DB_LOG_BUFFER_FULL:
		errno = ENOBUFS;
		break;
	case DB_DONOTINDEX:
	case DB_KEYEMPTY:
	case DB_FOREIGN_CONFLICT:
	case DB_PAGE_NOTFOUND:
	case DB_SECONDARY_BAD:
		errno = ENOKEY;
		break;
	case DB_KEYEXIST:
		errno = EACCES;
		break;
	case DB_LOCK_DEADLOCK:
		errno = EDEADLK;
		break;
	case DB_LOCK_NOTGRANTED:
		errno = ENOLCK;
		break;
	case DB_NOSERVER:
	case DB_NOSERVER_HOME:
	case DB_NOSERVER_ID:
	case DB_REP_DUPMASTER:
	case DB_REP_HANDLE_DEAD:
	case DB_REP_HOLDELECTION:
	case DB_REP_IGNORE:
	case DB_REP_ISPERM:
	case DB_REP_JOIN_FAILURE:
	case DB_REP_LEASE_EXPIRED:
	case DB_REP_LOCKOUT:
	case DB_REP_NEWSITE:
	case DB_REP_NOTPERM:
	case DB_REP_UNAVAIL:
		errno = EREMOTEIO;
		break;
	case DB_NOTFOUND:
		errno = ENODATA;
		break;
	case DB_OLD_VERSION:
	case DB_VERSION_MISMATCH:
		errno = ENOEXEC;
		break;
	case DB_RUNRECOVERY:
	case DB_VERIFY_BAD:
		errno = ENOTRECOVERABLE;
		break;
	default:
		errno = ENOSYS;
		break;
	}
}

