/* This file is #include'd by libtlspool.c */
#define closesocket(s) close(s)

int os_sendmsg_command(pool_handle_t poolfd, struct tlspool_command *cmd, int fd) {
	struct iovec iov;
	struct cmsghdr *cmsg;
	struct msghdr mh = { 0 };
	iov.iov_base = &cmd;
	iov.iov_len = sizeof(cmd);
	mh.msg_iov = &iov;
	mh.msg_iovlen = 1;
	if (fd >= 0) {
		char anc[CMSG_SPACE(sizeof(int))];
		mh.msg_control = anc;
		mh.msg_controllen = sizeof (anc);
		cmsg = CMSG_FIRSTHDR (&mh);
		cmsg->cmsg_level = SOL_SOCKET;
		cmsg->cmsg_type = SCM_RIGHTS;
		*(int *)CMSG_DATA(cmsg) = fd;
		cmsg->cmsg_len = CMSG_LEN(sizeof(int));
	}
}


int os_recvmsg_command(pool_handle_t poolfd, struct tlspool_command *cmd) {
	struct iovec iov;
	struct cmsghdr *cmsg;
	struct msghdr mh = { 0 };
	iov.iov_base = cmd;
	iov.iov_len = sizeof (struct tlspool_command);
	mh.msg_iov = &iov;
	mh.msg_iovlen = 1;
	//NOT-USED// mh.msg_control = anc;
	//NOT-USED// mh.msg_controllen = sizeof (anc);
	return recvmsg (poolfd, &mh, MSG_NOSIGNAL);
}
/*
 * converts IPPROTO_* to SOCK_*, returns -1 if invalid protocol
 */
int ipproto_to_sockettype(uint8_t ipproto) {
	return ipproto == IPPROTO_TCP ? SOCK_STREAM : ipproto == IPPROTO_UDP ? SOCK_DGRAM : ipproto == IPPROTO_SCTP ? SOCK_SEQPACKET : -1;
}

/*
 * The namedconnect() function is called by tlspool_starttls() when the
 * identities have been exchanged, and established, in the TLS handshake.
 * This is the point at which a connection to the plaintext side is
 * needed, and a callback to namedconnect() is made to find a handle for
 * it.  The function is called with a version of the tlsdata that has
 * been updated by the TLS Pool to hold the local and remote identities. 
 *
 * When the namedconnect argument passed to tlspool_starttls() is NULL,
 * this default function is used instead of the possible override by the
 * caller.  This interprets the privdata handle as an (int *) holding
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
 * The return value should be -1 on error, with errno set, or it should
 * be a valid file handle that can be passed back to the TLS Pool to
 * connect to.
 */
int tlspool_namedconnect_default (starttls_t *tlsdata, void *privdata) {
	int plainfd;
	int soxx[2];
	int type = ipproto_to_sockettype (tlsdata->ipproto);
	if (type == -1) {
		errno = EINVAL;
		return -1;
	}
	if (socketpair (AF_UNIX, type, 0, soxx) == 0)
	{
		// printf("DEBUG: socketpair succeeded\n");
		/* Socketpair created */
		plainfd = soxx [0];
		* (int *) privdata = soxx [1];
	} else {
		/* Socketpair failed */
		// printf("DEBUG: socketpair failed\n");
		plainfd = -1;
	}
	return plainfd;
}

/* Determine an upper limit for simultaneous STARTTLS threads, based on the
 * number of available file descriptors.  Note: The result is cached, so
 * don't use root to increase beyond max in setrlimit() after calling this.
 */
int tlspool_simultaneous_starttls(void) {
	static int simu = -1;
	if (simu < 0) {
		struct rlimit rlimit_nofile;
		if (getrlimit (RLIMIT_NOFILE, &rlimit_nofile) == -1) {
			syslog (LOG_NOTICE, "Failed to determine simultaneous STARTTLS: %s", strerror (errno));
			rlimit_nofile.rlim_max = 1024;  // Pick something
		}
		simu = rlimit_nofile.rlim_max / 2;  // 2 FDs per STARTTLS
	}
	return simu;
}

int os_usleep(unsigned int usec) {
	return usleep(usec);
}

pool_handle_t open_pool (void *path) {
	struct sockaddr_un sun;
	//
	// Setup path information -- value and size were checked
	memset (&sun, 0, sizeof (sun));
	strcpy (sun.sun_path, (char *) path);
	sun.sun_family = AF_UNIX;
	pool_handle_t newpoolfd = socket (AF_UNIX, SOCK_STREAM, 0);
	if (newpoolfd != INVALID_POOL_HANDLE) {
		if (connect (newpoolfd, (struct sockaddr *) &sun, SUN_LEN (&sun)) != 0) {
			tlspool_close_poolhandle (newpoolfd);
			newpoolfd = INVALID_POOL_HANDLE;
		}
	}
// printf ("DEBUG: Trying new poolfd %d for path %s\n", poolfd, sun.sun_path);
	return newpoolfd;
}
