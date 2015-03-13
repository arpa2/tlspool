/* tlspool/libfun.c -- Library function for starttls go-get-it */


#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <syslog.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/select.h>

#include <unistd.h>

#include <tlspool/starttls.h>
#include <tlspool/commands.h>


/* The library function for starttls, which is normally called through one
 * of the two inline variations below, which start client and server sides.
 */
int tlspool_socket (char *path) {
	static int poolfd = -1;	/* Kept open until program termination */
/*
	if (poolfd != -1) {
		fd_set fdtest;
		struct timeval fdtout;
		FD_ZERO (&fdtest);
		FD_SET (poolfd, &fdtest);
		// select() with timeout 0.000000 becomes a quick poll
		fdtout.tv_sec  = 0;
		fdtout.tv_usec = 0;
		// Select may return -1 on error, 1 on fd-except, 0 on no change
		if (select (poolfd + 1, NULL, NULL, &fdtest, &fdtout) != 0) {
			close (poolfd);	// Likely to fail silently
			errno = 0;
			poolfd = -1;
		}
	}
*/
/*
	if (poolfd != -1) {
		struct sockaddr_un sun;
		socklen_t sunlen = sizeof (sun);
		if (getpeername (poolfd, (struct sockaddr *) &sun, &sunlen) == -1) {
			close (poolfd);	// Likely to fail silently
			errno = 0;
			poolfd = -1;
		}
	}
*/
	if (poolfd == -1) {
		struct sockaddr_un sun;
		if (!path) {
			path = TLSPOOL_DEFAULT_SOCKET_PATH;
		}
		if (strlen (path) + 1 > sizeof (sun.sun_path)) {
			errno = ENAMETOOLONG;
		}
		bzero (&sun, sizeof (sun));
		strcpy (sun.sun_path, path);
		sun.sun_family = AF_UNIX;
		poolfd = socket (AF_UNIX, SOCK_STREAM, 0);
		if (poolfd == -1) {
			return -1;
		}
		if (connect (poolfd, (struct sockaddr *) &sun, SUN_LEN (&sun)) == -1) {
			close (poolfd);
			poolfd = -1;
		}
	}
	return poolfd;
}



/* The library function for starttls, which is normally called through one
 * of the two inline variations below, which start client and server sides.
 *
 * A non-zero server flag indicates that the connection is protected from
 * the server side, although the flags may modify this somewhat.  The
 * checkname() function is only used for server connections.
 * 
 * The cryptfd handle supplies the TLS connection that is assumed to have
 * been setup.  When the function ends, either in success or failure, this
 * handle will no longer be available to the caller; the responsibility of
 * closing it is passed on to the function and/or the TLS Pool.
 *
 * The tlsdata structure will be copied into the command structure,
 * and upon completion it will be copied back.  You can use it to
 * communicate flags, protocols and other parameters, including the
 * most important settings -- local and remote identifiers.  See
 * the socket protocol document for details.
 *
 * The privdata handle is used in conjunction with the namedconnect() call;
 * it is passed on to connect the latter to the context from which it was
 * called and is not further acted upon by this function.
 *
 * The namedconnect() function is called when the identities have been
 * exchanged, and established, in the TLS handshake.  This is the point
 * at which a connection to the plaintext side is needed, and a callback
 * to namedconnect() is made to find a handle for it.  The function is
 * called with a version of the tlsdata that has been updated by the
 * TLS Pool to hold the local and remote identities.  The return value
 * should be -1 on error, with errno set, or it should be a valid file
 * handle that can be passed back to the TLS Pool to connect to.
 *
 * When the namedconnect argument passed is NULL, default behaviour is
 * triggered.  This interprets the privdata handle as an (int *) holding
 * a file descriptor.  If its value is valid, that is, >= 0, it will be
 * returned directly; otherwise, a socketpair is constructed, one of the
 * sockets is stored in privdata for use by the caller and the other is
 * returned as the connected file descriptor for use by the TLS Pool.
 * This means that the privdata must be properly initialised for this
 * use, with either -1 (to create a socketpair) or the TLS Pool's
 * plaintext file descriptor endpoint.  The file handle returned in
 * privdata, if it is >= 0, should be closed by the caller, both in case
 * of success and failure.
 *
 * This function returns zero on success, and -1 on failure.  In case of
 * failure, errno will be set.
 */
int _starttls_libfun (int server, int cryptfd, starttls_t *tlsdata,
			void *privdata,
			int namedconnect (starttls_t *tlsdata,void *privdata)) {
	struct tlspool_command cmd;
	int poolfd = -1;
	int plainfd = -1;
	int sentfd = -1;
	char anc [CMSG_SPACE(sizeof (int))];
	struct iovec iov;
	struct cmsghdr *cmsg;
	struct msghdr mh = { 0 };
	int processing;

	/* Prepare command structure */
	poolfd = tlspool_socket (NULL);
	if (poolfd == -1) {
		close (cryptfd);
		return -1;
	}
	bzero (&cmd, sizeof (cmd));	/* Do not leak old stack info */
	cmd.pio_reqid = 666;	/* Static: No asynchronous behaviour */
	cmd.pio_cbid = 0;
	cmd.pio_cmd = server? PIOC_STARTTLS_SERVER_V2: PIOC_STARTTLS_CLIENT_V2;
	memcpy (&cmd.pio_data.pioc_starttls, tlsdata, sizeof (struct pioc_starttls));

	/* Send the request */
	iov.iov_base = &cmd;
	iov.iov_len = sizeof (cmd);
	mh.msg_iov = &iov;
	mh.msg_iovlen = 1;
	mh.msg_control = anc;
	mh.msg_controllen = sizeof (anc);
	cmsg = CMSG_FIRSTHDR (&mh);
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_RIGHTS;
	* (int *) CMSG_DATA (cmsg) = cryptfd;	/* cannot close it yet */
	cmsg->cmsg_len = CMSG_LEN (sizeof (int));
	if (sendmsg (poolfd, &mh, 0) == -1) {
		close (cryptfd);
		return -1;
	}
	sentfd = cryptfd;  /* Close anytime after response and before fn end */

	/* Handle responses until success or error */
	processing = 1;
	while (processing) {
		mh.msg_control = anc;
		mh.msg_controllen = sizeof (anc);
		if (recvmsg (poolfd, &mh, 0) == -1) {
			close (sentfd);
			return -1;
		}
		switch (cmd.pio_cmd) {
		case PIOC_ERROR_V1:
			/* Bad luck, we failed */
			errno = cmd.pio_data.pioc_error.tlserrno;
			syslog (LOG_INFO, "TLS Pool error to _starttls_libfun(): %s", cmd.pio_data.pioc_error.message);
			close (sentfd);
			return -1;
		case PIOC_PLAINTEXT_CONNECT_V2:
			if (namedconnect) {
				plainfd =  namedconnect (tlsdata, privdata);
			} else {
				/* default namedconnect() implementation */
				plainfd = * (int *) privdata;
				if (plainfd < 0) {
					int soxx [2];
					//TODO// Setup for TCP, UDP, SCTP
					if (socketpair (AF_UNIX, SOCK_SEQPACKET, 0, soxx) == 0) {
						/* Socketpair created */
						plainfd = soxx [0];
						* (int *) privdata = soxx [1];
					} else {
						/* Socketpair failed */
						cmd.pio_cmd = PIOC_ERROR_V1;
						cmd.pio_data.pioc_error.tlserrno = errno;
						plainfd = -1;
					}
				}
			}
			/* We now have a value to send in plainfd */
			mh.msg_control = anc;
			mh.msg_controllen = sizeof (anc);
			cmsg = CMSG_FIRSTHDR (&mh);
			cmsg->cmsg_level = SOL_SOCKET;
			cmsg->cmsg_type = SCM_RIGHTS;
			* (int *) CMSG_DATA (cmsg) = plainfd;
			cmsg->cmsg_len = CMSG_LEN (sizeof (int));
			/* Setup plainfd in sentfd, for delayed closing */
			if (sentfd >= 0) {
				close (sentfd);
			}
			sentfd = plainfd;
			/* Now supply plainfd in the callback response */
			if (sendmsg (poolfd, &mh, 0) == -1) {
				close (sentfd);
				return -1;
			}
			break;	// Loop around and try again
		case PIOC_STARTTLS_CLIENT_V2:
		case PIOC_STARTTLS_SERVER_V2:
			/* Wheee!!! we're done */
			processing = 0;
			break;
		default:
			/* V2 protocol error */
			errno = EPROTO;
			close (sentfd);
			return -1;
		}
	}

	/* Close the now-duplicated or now-erradicated plaintext fd */
	close (sentfd);

	memcpy (tlsdata, &cmd.pio_data.pioc_starttls, sizeof (struct pioc_starttls));
	return 0;
}


