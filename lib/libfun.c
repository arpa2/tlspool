/* tlspool/libfun.c -- Library function for starttls go-get-it */


#include <stdlib.h>
#include <errno.h>
#include <string.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/socket_un.h>

#include <tlspool/starttls.h>
#include <tlspool/commands.h>


/* The library function for starttls, which is normally called through one
 * of the two inline variations below, which start client and server sides.
 */
int tlspool_socket (char *path) {
	int poolfd = -1;
	//TODO// Possibly really test if a poolfd is valid?
	if (poolfd == -1) {
		struct sockaddr_un sun;
		int sunlen;
		if (!path) {
			path = TLSPOOL_DEFAULT_SOCKET_PATH;
		}
		sunlen = strlen (path);
		if (sunlen + 1 > sizeof (sun.sun_path)) {
			errno = ENAMETOOLONG;
		}
		strcpy (sun.sun_path, path);
		sunlen += sizeof (sun.sun_family);
		sun.sun_family = AF_UNIX;
		poolfd = socket (SOCK_STREAM, AF_UNIX, 0);
		if (poolfd == -1) {
			return -1;
		}
		if (connect (poolfd, (struct sockaddr *) &sun, sunlen) == -1) {
			close (poolfd);
			poolfd = -1;
		}
	}
	return poolfd;
}



/* The library function for starttls, which is normally called through one
 * of the two inline variations below, which start client and server sides.
 *
 * The tlsdata structure will be copied into the command structure,
 * and upon completion it will be copied back.  You can use it to
 * communicate flags, protocols and other parameters, including the
 * most important settings -- local and remote identifiers.  See
 * the socket protocol document for details.
 * TODO: Use iovec() instead of memcpy() to optimise sending.
 *
 * The checksni() function is a callback that is used to verify if a
 * proposed local identifier is acceptable.  The buffer along with its
 * size including trailing NUL character is provided, and may be
 * reviewed.  Note that the actual string stored in the buffer may be
 * shorter; the room is provided to offer place for alternate proposals
 * of local identities.  The function may disagree with a name without
 * proposing an alternative by setting the buffer to an emptry string or
 * by returning zero.  Non-zero returned from checksni() means to use
 * the buffer value as it is upon return.
 *
 * The function returns -1 on error, and sets errno appropriately.
 */
int _starttls_libfun (int server, int fd, struct pioc_starttls *tlsdata, int checksni (char *,size_t)) {
	struct tlspool_command cmd;
	int poolfd;
	struct anc [CMSG_SPACE(sizeof (int))];
	struct iovec iov;
	struct cmsghdr *cmsg;
	int processing = 1;

	/* Prepare command structure */
	poolfd = tlspool_socket (NULL);
	if (poolfd == -1) {
		close (fd);
		return -1;
	}
	bzero (&cmd, sizeof (cmd));	/* Do not leak old stack info */
	cmd.pio_reqid = 666;	/* Static: No asynchronous behaviour */
	cmd.pio_cbid = 0;
	cmd.pio_cmd = server? PIOC_STARTTLS_SERVER_V1: PIOC_STARTTLS_CLIENT_V1;
	memcpy (&cmd.pioc_data.pioc_starttls, tlsdata, sizeof (struct pioc_starttls));

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
	cmsg->cmsg_len = CMSG_LEN (sizeof (int));
	* (int *) CMSG_DATA (cmsg) = fd;
	if (sendmsg (poolfd, &mh, 0) == -1) {
		return -1;
	}

	/* Handle responses until success or error */
	while (processing) {
		mh.msg_control = anc;
		mh.msg_controllen = sizeof (anc);
		if (recvmsg (sox, &mh, 0) == -1) {
			return -1;
		}
		switch (cmd.pio_cmd) {
		case PIOC_ERROR_V1:
			/* Bad luck, we failed */
			//TODO// Send errno + message to syslog()
			errno = cmd.pioc_data.pioc_error.tlserrno;
			return -1;
		case PIOC_STARTTLS_LOCALID:
			/* Check if a proposed local name is acceptable */
			if (server && check_sni && check_sni (cmd.pio_data.pioc_localid, 128)) {
				;	// Use the value now stored in localid
			} else {
				*cmd.pio_data.pioc_localid = 0;
			}
			mh.control = NULL;
			mh.controllen = 0;
			if (sendmsg (poolfd, &mh, 0) == -1) {
				return -1;
			}
			break;
		case PIOC_STARTTLS_CLIENT_V1:
		case PIOC_STARTTLS_SERVER_V1:
			/* Wheee!!! we're done */
			processing = 0;
			break;
		default:
			/* V1 protocol error */
			errno = EPROTO;
			return -1;
		}
	}

	/* Return command output data */
	cmsg = CMSG_FIRSTHEADER (&mh);
	if (!cmsg) {
		errno = EPROTO;
		return -1;
	}
	memcpy (tlsdata, &cmd.pioc_data.pioc_starttls, sizeof (struct pioc_starttls));
	return * (int *) CMSG_DATA (cmsg)
}


