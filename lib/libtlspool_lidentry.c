/* tlspool/libfun.c -- Library function for starttls go-get-it */

#include "whoami.h"

#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <syslog.h>

#include <unistd.h>
#include <pthread.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/select.h>
#include <sys/resource.h>

#include <tlspool/starttls.h>
#include <tlspool/commands.h>


/* Cleanup routine */
static void tlspool_localid_service_closepool (void *poolfdptr) {
	int poolfd = * (int *) poolfdptr;
	if (poolfd >= 0) {
		close (poolfd);
	}
}


/* The library function to service local identity callbacks.  It registers
 * with the TLS Pool and will service callback requests until it is no
 * longer welcomed.  Of course, if another process already has a claim on
 * this functionality, the service offering will not be welcome from the
 * start.
 *
 * This function differs from most other TLS Pool library functions in
 * setting up a private socket.  This helps to avoid the overhead in the
 * foreseeable applications that only do this; it also helps to close
 * down the exclusive claim on local identity resolution when (part of)
 * the program is torn down.  The function has been built to cleanup
 * properly when it is subjected to pthread_cancel().
 *
 * The path parameter offers a mechanism to specify the socket path.  When
 * set to NULL, the library's compiled-in default path will be used.
 *
 * In terms of linking, this routine is a separate archive object.  This
 * minimizes the amount of code carried around in statically linked binaries.
 *
 * This function returns -1 on error, or 0 on success.
 */
int tlspool_localid_service (char *path, uint32_t regflags, int responsetimeout, char * (*cb) (lidentry_t *entry, void *data), void *data) {
	struct sockaddr_un sun;
	int poolfd = -1;
	struct tlspool_command cmd;
	char *cberr = NULL;

	/* Access the TLS Pool socket */
	if (path == NULL) {
		path = tlspool_configvar (NULL, "daemon_pidfile");
	}
	if (path == NULL) {
		path = TLSPOOL_DEFAULT_SOCKET_PATH;
	}
	if (strlen (path) + 1 > sizeof (sun.sun_path)) {
		errno = EINVAL;
		return -1;
	}
	memset (&sun, 0, sizeof (sun));
	sun.sun_family = AF_UNIX;
	strcpy (sun.sun_path, path);
	pthread_cleanup_push (tlspool_localid_service_closepool, &poolfd);
	poolfd = socket (AF_UNIX, SOCK_STREAM, 0);
	if (poolfd < 0) {
		return -1;
	}
	if (connect (poolfd, (struct sockaddr *) &sun, sizeof (sun)) == -1) {
		close (poolfd);
		poolfd = -1;
		return -1;
	}

	/* Prepare command structure */
	memset (&cmd, 0, sizeof (cmd));	/* Do not leak old stack info */
	cmd.pio_cbid = 0;
	cmd.pio_cmd = PIOC_LIDENTRY_REGISTER_V2;
	cmd.pio_data.pioc_lidentry.flags = regflags;
	cmd.pio_data.pioc_lidentry.timeout = responsetimeout;

	/* Loop forever... or until an error occurs */
	while (1) {

		/* send the request or, when looping, the callback result */
//DEBUG// printf ("DEBUG: LIDENTRY command 0x%08lx with cbid=%d and flags 0x%08lx\n", cmd.pio_cmd, cmd.pio_cbid, cmd.pio_data.pioc_lidentry.flags);
		if (send (poolfd, &cmd, sizeof (cmd), MSG_NOSIGNAL) == -1) {
			// errno inherited from send()
			// let SIGPIPE be reported as EPIPE
			close (poolfd);
			return -1;
		}

		/* receive and process the response */
		if (recv (poolfd, &cmd, sizeof (cmd), MSG_NOSIGNAL) == -1) {
			// Let SIGPIPE be reported as EPIPE
			// errno inherited from recv()
			close (poolfd);
			return -1;
		}
//DEBUG// printf ("DEBUG: LIDENTRY callback command 0x%08lx with cbid=%d and flags 0x%08lx\n", cmd.pio_cmd, cmd.pio_cbid, cmd.pio_data.pioc_lidentry.flags);
		switch (cmd.pio_cmd) {
		case PIOC_LIDENTRY_CALLBACK_V2:
			cberr = (*cb) (&cmd.pio_data.pioc_lidentry, data);
			//TODO// Claim on regent lost?
			break;
		case PIOC_ERROR_V2:
			errno = cmd.pio_data.pioc_error.tlserrno;
			syslog (LOG_INFO, "TLS Pool error to tlspool_localid_service(): %s", cmd.pio_data.pioc_error.message);
			close (poolfd);
			return -1;
		default:
			errno = EPROTO;
			return -1;
		}
		if (cberr != NULL) {
			cmd.pio_cmd = PIOC_ERROR_V2;
			cmd.pio_data.pioc_error.tlserrno = errno;
			strncpy (cmd.pio_data.pioc_error.message,
				cberr,
				sizeof (cmd.pio_data.pioc_error.message));
			// Next loop will send error to TLS Pool, which will
			// bounce the error back to us so we can report it too
		}
	}

	/* Never end up here... */
	pthread_cleanup_pop (1);
	return 0;
}

