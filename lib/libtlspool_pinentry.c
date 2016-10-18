/* tlspool/libfun.c -- Library function for starttls go-get-it */

#include "whoami.h"

#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <syslog.h>

#include <unistd.h>
#include <pthread.h>

#include <tlspool/starttls.h>
#include <tlspool/commands.h>

#ifdef WINDOWS_PORT
#include <winsock2.h>
#else
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/select.h>
#include <sys/resource.h>
#endif

/* Cleanup routine */
static void tlspool_pin_service_closepool (void *poolfdptr) {
	pool_handle_t poolfd = * (pool_handle_t  *) poolfdptr;
	if (poolfd != INVALID_POOL_HANDLE) {
		tlspool_close_poolhandle (poolfd);
	}
}


/* The library function to service PIN entry callbacks.  It registers
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
int tlspool_pin_service (char *path, uint32_t regflags, int responsetimeout_usec, void (*cb) (struct pioc_pinentry *entry, void *data), void *data) {
#ifdef WINDOWS_PORT
printf("tlspool_pin_service(%s, %d, %d, %p, %p)\n", path, regflags, responsetimeout_usec, cb, data);
#else
	struct sockaddr_un sun;
#endif
	pool_handle_t poolfd = INVALID_POOL_HANDLE;;
	struct tlspool_command cmd;

#ifdef WINDOWS_PORT
	poolfd = open_named_pipe ((LPCTSTR) path);
	printf ("DEBUG: poolfd = %d\n", poolfd);
	if (poolfd == INVALID_POOL_HANDLE) {
		return -1;
	}
#else
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
	pthread_cleanup_push (tlspool_pin_service_closepool, &poolfd);
	poolfd = socket (AF_UNIX, SOCK_STREAM, 0);
	if (poolfd < 0) {
		return -1;
	}
	if (connect (poolfd, (struct sockaddr *) &sun, sizeof (sun)) == -1) {
		close (poolfd);
		poolfd = -1;
		return -1;
	}
#endif

	/* Prepare command structure */
	memset (&cmd, 0, sizeof (cmd));	/* Do not leak old stack info */
	cmd.pio_cbid = 0;
	cmd.pio_cmd = PIOC_PINENTRY_V2;
	cmd.pio_data.pioc_pinentry.flags = regflags;
	cmd.pio_data.pioc_pinentry.timeout_us = responsetimeout_usec;

	/* Loop forever... or until an error occurs */
	while (1) {

		/* send the request or, when looping, the callback result */
//DEBUG// printf ("DEBUG: PINENTRY command 0x%08lx with cbid=%d and flags 0x%08lx\n", cmd.pio_cmd, cmd.pio_cbid, cmd.pio_data.pioc_pinentry.flags);
#ifdef WINDOWS_PORT
		if (np_send_command(poolfd, &cmd) == -1) {
#else
		if (send (poolfd, &cmd, sizeof (cmd), MSG_NOSIGNAL) == -1) {
#endif
			// errno inherited from send()
			// let SIGPIPE be reported as EPIPE
			tlspool_close_poolhandle (poolfd);
			return -1;
		}

		/* Erase the password that has just been sent */
		memset (&cmd.pio_data.pioc_pinentry.pin,
				0,
				sizeof (cmd.pio_data.pioc_pinentry.pin));

		/* receive and process the response */
#ifdef WINDOWS_PORT
		if (np_recv_command(poolfd, &cmd) == -1) {
#else
		if (recv (poolfd, &cmd, sizeof (cmd), MSG_NOSIGNAL) == -1) {
#endif
			// Let SIGPIPE be reported as EPIPE
			// errno inherited from recv()
			tlspool_close_poolhandle (poolfd);
			return -1;
		}
//DEBUG// printf ("DEBUG: PINENTRY callback command 0x%08lx with cbid=%d and flags 0x%08lx\n", cmd.pio_cmd, cmd.pio_cbid, cmd.pio_data.pioc_pinentry.flags);
		switch (cmd.pio_cmd) {
		case PIOC_PINENTRY_V2:
			(*cb) (&cmd.pio_data.pioc_pinentry, data);
			//TODO// Claim on regent lost?
			break;
		case PIOC_ERROR_V2:
			errno = cmd.pio_data.pioc_error.tlserrno;
			syslog (LOG_INFO, "TLS Pool error to tlspool_localid_service(): %s", cmd.pio_data.pioc_error.message);
			tlspool_close_poolhandle (poolfd);
			return -1;
		default:
			errno = EPROTO;
			tlspool_close_poolhandle (poolfd);
			return -1;
		}
	}

#ifndef WINDOWS_PORT
	/* Never end up here... */
	pthread_cleanup_pop (1);
#endif
	return 0;
}

