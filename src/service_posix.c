/* this file is #include'd by service.c */

static int num_sox = 0;
static struct soxinfo soxinfo [1024];
static struct pollfd soxpoll [1024];

/* Register a socket.  It is assumed that first all server sockets register */
static void register_socket (pool_handle_t sox, uint32_t soxinfo_flags) {
	int flags = fcntl (sox, F_GETFD);
	flags |= O_NONBLOCK;
	fcntl (sox, F_SETFD, flags);
	//TODO// if (soxinfo == NULL) {
	//TODO// 	soxinfo = calloc ()
	//TODO// }
	if (num_sox == 1024) {
		tlog (TLOG_UNIXSOCK, LOG_CRIT, "Cannot allocate more than 1024 server sockets");
		exit (1);
	}
	soxpoll [num_sox].fd = sox;
	soxpoll [num_sox].events = POLLIN;
	soxpoll [num_sox].revents = 0;
	soxinfo [num_sox].flags = soxinfo_flags;
	soxinfo [num_sox].cbq = NULL;
	num_sox++;
}

/* TODO: This may copy information back and thereby avoid processing in the
 * current loop passthrough.  No problem, poll() will show it once more. */
static void unregister_client_socket_byindex (int soxidx) {
	pool_handle_t sox = soxpoll [soxidx].fd;
	free_callbacks_by_clientfd (sox);
	free_commands_by_clientfd (sox);
	pinentry_forget_clientfd (sox);
	lidentry_forget_clientfd (sox);
	ctlkey_close_ctlfd (sox);
	num_sox--;
	if (soxidx < num_sox) {
		memcpy (&soxinfo [soxidx], &soxinfo [num_sox], sizeof (*soxinfo));
		memcpy (&soxpoll [soxidx], &soxpoll [num_sox], sizeof (*soxpoll));
	}
}

static int os_send_command (struct command *cmd, int passfd)
{
	char anc [CMSG_SPACE(sizeof (int))];
	struct iovec iov;
	struct msghdr mh;
	struct cmsghdr *cmsg;

	memset (anc, 0, sizeof (anc));
	memset (&iov, 0, sizeof (iov));
	memset (&mh, 0, sizeof (mh));
	iov.iov_base = &cmd->cmd;
	iov.iov_len = sizeof (cmd->cmd);
	mh.msg_iov = &iov;
	mh.msg_iovlen = 1;
	if (passfd >= 0) {
		mh.msg_control = anc;
		mh.msg_controllen = sizeof (anc);
		cmsg = CMSG_FIRSTHDR (&mh);
		cmsg->cmsg_level = SOL_SOCKET;
		cmsg->cmsg_type = SCM_RIGHTS;
		cmsg->cmsg_len = CMSG_LEN (sizeof (int));
		* (int *) CMSG_DATA (cmsg) = passfd;
	}
	tlog (TLOG_UNIXSOCK, LOG_DEBUG, "Sending command 0x%08x and fd %d to socket %d", cmd->cmd.pio_cmd, passfd, (int) cmd->clientfd);
	if (sendmsg (cmd->clientfd, &mh, MSG_NOSIGNAL) == -1) {
		//TODO// Differentiate behaviour based on errno?
		perror ("Failed to send command");
		return 0;
	} else {
		tlog (TLOG_UNIXSOCK, LOG_DEBUG, "Sent command code 0x%08x", cmd->cmd.pio_cmd);
		return 1;
	}
}

/* Receive a command.  Return nonzero on success, zero on failure. */
static int receive_command (pool_handle_t sox, struct command *cmd) {
	int newfds [2];
	int newfdcnt = 0;
	char anc [CMSG_SPACE (sizeof (int))];
	struct iovec iov;
	struct msghdr mh = { 0 };
	struct cmsghdr *cmsg;

	iov.iov_base = &cmd->cmd;
	iov.iov_len = sizeof (cmd->cmd);
	mh.msg_iov = &iov;
	mh.msg_iovlen = 1;
	mh.msg_control = anc;
	mh.msg_controllen = sizeof (anc);

	if (recvmsg (sox, &mh, MSG_NOSIGNAL) == -1) {
		//TODO// Differentiate behaviour based on errno?
		perror ("Failed to receive command");
		return 0;
	}
	tlog (TLOG_UNIXSOCK, LOG_DEBUG, "Received command request code 0x%08x with cbid=%d over fd=%d", cmd->cmd.pio_cmd, cmd->cmd.pio_cbid, sox);

	cmsg = CMSG_FIRSTHDR (&mh);
	//TODO// It is more general to look at all FDs passed, close all 2+
	if (cmsg && (cmsg->cmsg_len == CMSG_LEN (sizeof (int)))) {
		if ((cmsg->cmsg_level == SOL_SOCKET) && (cmsg->cmsg_type == SCM_RIGHTS)) {
			if (cmd->passfd == -1) {
				cmd->passfd = * (int *) CMSG_DATA (cmsg);
				tlog (TLOG_UNIXSOCK, LOG_DEBUG, "Received file descriptor as %d", cmd->passfd);
			} else {
				int superfd = * (int *) CMSG_DATA (cmsg);
				tlog (TLOG_UNIXSOCK, LOG_ERR, "Received superfluous file descriptor as %d", superfd);
				close (superfd);
			}
		}
		cmsg = CMSG_NXTHDR (&mh, cmsg);
	}

	return 1;
}

void register_server_socket (pool_handle_t srvsox) {
	register_socket (srvsox, SOF_SERVER);
}


void register_client_socket (pool_handle_t clisox) {
	register_socket (clisox, SOF_CLIENT);
}

/* Pickup on activity and process it.  Processing may mean a number of things:
 *  - to try an accept() on a server socket (ignoring it upon EAGAIN)
 *  - to trigger a thread that is hoping writing after EAGAIN
 *  - to read a message and further process it
 */
void process_activity (pool_handle_t sox, int soxidx, struct soxinfo *soxi, short int revents) {
	if (revents & POLLOUT) {
		//TODO// signal waiting thread that it may continue
		tlog (TLOG_UNIXSOCK, LOG_CRIT, "Eekk!!  Could send a packet?!?  Unregistering client");
		unregister_client_socket_byindex (soxidx);
		tlspool_close_poolhandle (sox);
	}
	if (revents & POLLIN) {
		if (soxi->flags & SOF_SERVER) {
			struct sockaddr sa;
			socklen_t salen = sizeof (sa);
			pool_handle_t newsox = accept (sox, &sa, &salen);
			if (newsox != INVALID_POOL_HANDLE) {
				tlog (TLOG_UNIXSOCK, LOG_NOTICE, "Received incoming connection.  Registering it");
				register_client_socket (newsox);
			}
		}
		if (soxi->flags & SOF_CLIENT) {
			struct command *cmd = allocate_command_for_clientfd (sox);
			if (receive_command (sox, cmd)) {
				process_command (cmd);
			} else {
				tlog (TLOG_UNIXSOCK, LOG_ERR, "Failed to receive command request");
			}
		}
	}
}

static void os_run_service ()
{
	int polled;
	int i;
	tlog (TLOG_UNIXSOCK, LOG_DEBUG, "Polling %d sockets numbered %d, %d, %d, ...", num_sox, soxpoll [0].fd, soxpoll [1].fd, soxpoll [2].fd);
	while (polled = poll (soxpoll, num_sox, -1), polled > 0) {
		tlog (TLOG_UNIXSOCK, LOG_DEBUG, "Polled %d sockets, returned %d", num_sox, polled);
		for (i=0; i<num_sox; i++) {
			if (soxpoll [i].revents & (POLLHUP|POLLERR|POLLNVAL)) {
				pool_handle_t sox = soxpoll [i].fd;
				tlog (TLOG_UNIXSOCK, LOG_NOTICE, "Unregistering socket %d", sox);
				unregister_client_socket_byindex (i);
				close (sox);
				continue;
			} else if (soxpoll [i].revents) {
				tlog (TLOG_UNIXSOCK, LOG_DEBUG, "Socket %d has revents=%d", soxpoll [i].fd, soxpoll [i].revents);
				process_activity (soxpoll [i].fd, i, &soxinfo [i], soxpoll [i].revents);
			}
		}
		tlog (TLOG_UNIXSOCK, LOG_DEBUG, "Polling %d sockets numbered %d, %d, %d, ...", num_sox, soxpoll [0].fd, soxpoll [1].fd, soxpoll [2].fd);
	}
	if (stop_service) {
		tlog (TLOG_UNIXSOCK, LOG_NOTICE, "Service hangup in response to request");
	} else {
		tlog (TLOG_UNIXSOCK, LOG_DEBUG, "Polled %d sockets, returned %d", num_sox, polled);
		perror ("Failed to poll for activity");
	}
}
