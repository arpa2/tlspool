/* This file is #include'd by config.c */
void unlink_pidfile (void) {
#ifndef CONFIG_PARSE_ONLY
	unlink (configvars [CFGVAR_DAEMON_PIDFILE]);
#endif
}

void cfg_pidfile (char *item, int itemno, char *value) {
	static int fh = 0;
	if (fh) {
		fprintf (stderr, "You can specify only one PID file\n");
		exit (1);
	}
	cfg_setvar (item, CFGVAR_DAEMON_PIDFILE, value);
	atexit (unlink_pidfile);
#ifndef CONFIG_PARSE_ONLY
	fh = open (value, O_RDWR | O_CREAT, 0664);
	char pidbuf [10];
	if (fh < 0) {
		perror ("Failed to open PID file");
		exit (1);
	}
retry:
	if (flock (fh, LOCK_EX | LOCK_NB) != 0) {
		if (errno == EWOULDBLOCK) {
			pid_t oldpid;
			memset (pidbuf, 0, sizeof (pidbuf));
			read (fh, pidbuf, sizeof (pidbuf)-1);
			oldpid = atoi (pidbuf);
			if (kill_old_pid) {
				if (kill (oldpid, SIGHUP) == 0) {
					fprintf (stderr, "Sent hangup to old daemon with PID %s\n", pidbuf);
					sleep (1);
				}
				lseek (fh, 0, SEEK_SET);
				errno = 0;
				goto retry;
			}
			if (kill (oldpid, 0) != -1) {
				fprintf (stderr, "Another daemon owns the PID file: process %s", pidbuf);
				exit (1);
			}
		} else {
			perror ("Failed to own the PID file");
			exit (1);
		}
	}
	snprintf (pidbuf, sizeof (pidbuf)-1, "%d\n", getpid ());
	if (write (fh, pidbuf, strlen (pidbuf)) != strlen (pidbuf)) {
		perror ("Failed to write all bytes to PID file");
		exit (1);
	}
	ftruncate (fh, strlen (pidbuf));
	fsync (fh);
	//
	// Note: The file remains open -- to sustain the flock on it
	//
#endif /* CONFIG_PARSE_ONLY */
}

void cfg_socketname (char *item, int itemno, char *value) {
	struct sockaddr_un sun;
	int sox;
#ifndef CONFIG_PARSE_ONLY
#ifndef HAVE_SYSTEMD
	uid_t me = getuid ();
	gid_t my = getgid ();
	if (strlen (value) + 1 > sizeof (sun.sun_path)) {
		fprintf (stderr, "Socket path too long: %s\n", value);
		exit (1);
	}
	strcpy (sun.sun_path, value);
	sun.sun_family = AF_UNIX;
	if (configvars [CFGVAR_DAEMON_PIDFILE]) {
		//
		// Note: Only be so kind to unlink when PID file is owned
		//
		unlink (value);
	}
	sox = socket (AF_UNIX, SOCK_STREAM, 0);
	if (sox < 0) {
		perror ("Failed to open UNIX socket");
		exit (1);
	}
	if (bind (sox, (struct sockaddr *) &sun, SUN_LEN (&sun)) == -1) {
		perror ("Failed to bind to UNIX socket");
		exit (1);
	}
	if (listen (sox, 5) == -1) {
		perror ("Failed to listen to UNIX socket");
		exit (1);
	}
	//
	// Now continue to set uid, gid, mode for the socket
	//
	if (configvars [CFGVAR_SOCKET_USER]) {
		struct passwd *pwd = getpwnam (configvars [CFGVAR_SOCKET_USER]);
		if (!pwd) {
			fprintf (stderr, "Failed to find socket user %s\n", value);
			exit (1);
		}
		me = pwd->pw_uid;
	}
	if (configvars [CFGVAR_SOCKET_GROUP]) {
		struct group *grp = getgrnam (configvars [CFGVAR_SOCKET_GROUP]);
		if (!grp) {
			fprintf (stderr, "Failed to find socket group %s\n", value);
			exit (1);
		}
		my = grp->gr_gid;
	}
	if (chown (value, me, my) != 0) {
		perror ("Failed to change socket user/group");
		exit (1);
	}
	if (configvars [CFGVAR_SOCKET_MODE]) {
		int mode = strtoul (configvars [CFGVAR_SOCKET_MODE], NULL, 0);
		if (chmod (value, mode) != 0) {
			perror ("Failed to change socket mode");
			exit (1);
		}
	}
#else  /* HAVE_SYSTEMD */
	if (sd_listen_fds (0) != 1) {
		fprintf (stderr, "TLS Pool should have received one socket\n");
		exit (1);
	}
	sox = SD_LISTEN_FDS_START + 0;
#endif /* HAVE_SYSTEMD */
	register_server_socket (sox);
#endif /* CONFIG_PARSE_ONLY */
}

void cfg_user (char *item, int itemno, char *value) {
#ifdef DEBUG
	fprintf (stdout, "DEBUG: DECLARE %s AS %s\n", item, value);
#endif /* DEBUG */
#ifndef CONFIG_PARSE_ONLY
	struct passwd *pwd = getpwnam (value);
	if (!pwd) {
		fprintf (stderr, "Failed to find username %s\n", value);
		exit (1);
	}
	setuid (pwd->pw_uid);
#endif /* CONFIG_PARSE_ONLY */
}

void cfg_group (char *item, int itemno, char *value) {
#ifdef DEBUG
	fprintf (stdout, "DEBUG: DECLARE %s AS %s\n", item, value);
#endif /* DEBUG */
#ifndef CONFIG_PARSE_ONLY
	struct group *grp = getgrnam (value);
	if (!grp) {
		fprintf (stderr, "Failed to find group name %s\n", value);
		exit (1);
	}
	setgid (grp->gr_gid);
#endif /* CONFIG_PARSE_ONLY */
}

void cfg_chroot (char *item, int itemno, char *value) {
	if (chroot (value) != 0) {
		perror ("Failed to chroot");
		exit (1);
	}
}
