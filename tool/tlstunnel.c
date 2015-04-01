/* tlspool/tlstunnel.c -- Simple utility, forward TLS as TCP and vice versa */

#include <stdlib.h>
#include <stdio.h>
#include <stdio.h>
#include <string.h>
#include <pthread.h>
#include <fcntl.h>

#include <errno.h>
#include <poll.h>
#include <unistd.h>
#include <getopt.h>
#include <netdb.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <sys/select.h>
#include <sys/resource.h>

#include <tlspool/starttls.h>


static starttls_t tlsdata = {
	.flags = 0,
	.local = 0,
};

static char *chatcommand;
static char *tunnelcommand;
static int global_argc;
static char **global_argv;
static struct addrinfo *remoteaddrinfo;
static int role = -1;



#ifdef USING_STR2PORT_SOMEWHERE
int str2port (char *portstr) {
	char *portrest;
	long int retval = strtol (portstr, &portrest, 0);
	if (*portrest) {
		fprintf (stderr, "Not a port number: %s\n", portstr);
		exit (1);
	}
	if ((retval <= 0) || (retval > 65535)) {
		fprintf (stderr, "Port numbers range from 1 to 65535: %s\n", portstr);
		exit (1);
	}
	return (int) retval;
}
#endif


struct unixaddrinfo {
	struct addrinfo ai;
	struct sockaddr_un sa;
};

void parse_addrinfo (char *instr, char local_remote,
			struct addrinfo *hint, struct addrinfo **res) {
	while (*res != NULL) {
		res = &(*res)->ai_next;
	}
	if (!instr) {
		fprintf (stderr, "Specify -%c as either a socket pathname or a [host]:port\n", local_remote);
		exit (1);
	}
	if (instr [0] == '/') {
		struct unixaddrinfo *uai;
		/* Interpret instr as a UNIX domain socket's path name */
		uai = malloc (sizeof (struct unixaddrinfo));
		if (uai == NULL) {
			fprintf (stderr, "Out of memory allocating UNIX addrinfo\n");
			exit (1);
		}
		uai->ai.ai_flags = 0;
		uai->ai.ai_family = AF_UNIX;
		uai->ai.ai_socktype = hint->ai_socktype;
		uai->ai.ai_protocol = 0;
		uai->ai.ai_addrlen = sizeof (struct sockaddr_un);
		uai->ai.ai_addr = (struct sockaddr *) &uai->sa;
		uai->ai.ai_canonname = instr;
		uai->ai.ai_next = NULL;
		uai->sa.sun_family = AF_UNIX;
		if (strlen (instr) +1 > sizeof (uai->sa.sun_path)) {
			fprintf (stderr, "UNIX domain socket path %s too long\n", instr);
			exit (1);
		}
		strcpy (uai->sa.sun_path, instr);
		*res = &uai->ai;
	} else {
		/* Interpret instr as a host:port combination */
		char *port;
		int braket;
		port = strrchr (instr, ':');
		if (port == NULL) {
			fprintf (stderr, "Format -%c as either /unix/domain/path/name or as host:port\n", local_remote);
			exit (1);
		}
		if ((instr [0] == '[') && (port [-1] == ']')) {
			braket = 1;
			hint->ai_family = AF_INET6;
		} else {
			braket = 0;
			hint->ai_family = AF_UNSPEC;
		}
		port [-braket] = '\0';
		if (getaddrinfo (instr + braket, port+1, hint, res) != 0) {
			fprintf (stderr, "Syntax error in -%c paramater; use /uinx/domain/path/name or host:port\n", local_remote);
			exit (1);
		}
		port [-braket] = braket? ']': ':';
	}
}


int chat_builtin (int plainfd, char *progpath, int argc, char *argv []);
int chat (int plainfd) {
	int chatexit = 0;
	//
	// Without explicit chatcommand, invoke the builtin ppp-style chat
	if (chatcommand == NULL) {
		return chat_builtin (plainfd, tunnelcommand, global_argc, global_argv);
	}
	//
	// Fork off a STARTTLS chat session
	switch (fork ()) {
	case -1:
		perror ("Failed to fork ppp-style chat script");
		return 1;
	case 0:
		close (0);
		close (1);
		if ((dup2 (plainfd, 0) == -1) || (dup2 (plainfd, 1) == -1)) {
			fprintf (stderr, "Failed to connect plaintext to the %s interaction\n", tunnelcommand);
			exit (2);
		}
		fprintf (stderr, "Starting script + args: %s, %s, %s...\n", tunnelcommand, global_argv [1], global_argv [2]);
		execve (chatcommand, global_argv, NULL /*TODO:envp:params*/);
		perror ("Failed to start alternative to the ppp-style chat");
		exit (2);		// See tlstunnel-chat(8)
	default:
		wait (&chatexit);
		if (!WIFEXITED (chatexit)) {
			return 2;	// See tlstunnel-chat(8)
		}
		return WEXITSTATUS (chatexit);
	}
}



/* Format a UNIX domain socket path that may contain formatting characters:
 *
 * %L and %*L indicate the localid  negotiated in the TLS handshake;
 * %R and %*R indicate the remoteid negotiated in the TLS handshake;
 *
 * Note that a server has authenticated names, but a client does not, due
 * to the early stage in which it forms these addresses (before the TLS
 * handshake).
 *
 * The * is ignored for now, but may be used to prefix domain patterns.
 *
 * There currently is no support for iterators with DoNAI selectors, but
 * this is a logical extension (this function would recurse).
 */
int fmtcpy (char *dst, char *src, size_t dstsz, starttls_t *tlsdata) {
	while (src && *src) {
		size_t len;
		char *perc = strchr (src, '%');
		if (perc) {
			len = ((intptr_t) perc) - ((intptr_t) src);
		} else {
			len = strlen (src);
		}
		if (len + 1 > dstsz) {
			return -1;
		}
		memcpy (dst, src, len);
		src   += len;
		dst   += len;
		dstsz -= len;
		if (perc) {
			int star = *(++src) == '*';
			char *xtra = "";
			if (star) {
				src++;
			}
			switch (*src++) {
			case 'L':
				xtra = tlsdata->localid;
				break;
			case 'R':
				xtra = tlsdata->remoteid;
				break;
			default:
				return -1;
			}
			len = strnlen (xtra, 127);
			if (len + 1 > dstsz) {
				return -1;
			}
			memcpy (dst, xtra, len);
			dst   += len;
			dstsz -= len;
		}
	}
	*dst++ = '\0';
	return 0;
}


//TODO// Spark thread with:  fd, localaddrinfo, role, remoteaddrinfo, chatcommand, tlsdata, tunnelcommand, argc, argv; only dynamic is fd, localaddrinfo; thread negotiates session and then goes down; curtlsdata is a thread local variable

/* Data structure passed to connection handler threads */
struct fdinfo {
	int fd;
	struct addrinfo *localaddrinfo;
};

/* We will smuggle a file descriptor into the localaddrinfo field ai_family;
 * the value in ai_family is no longer needed, and it would be replicated in
 * ai_addr->sa_family as well as available through the getsockaddr() result.
 */
#define smuggle_fd ai_family


#ifdef NEED_THIS_WHEN_THE_CONNECTION_CLOSES_FINALLY
void cleanup_connection (void *vfdi) {
	struct fdinfo *fdi = vfdi;
	struct addrinfo *lai = fdi->localaddrinfo;
	if (lai->smuggle_fd < 0) {
		/* Correct UDP reversal so it will be selected again */
		lai->smuggle_fd = -lai->smuggle_fd;
	}
	if (fdi->fd != lai->smuggle_fd) {
		/* For TCP and SCTP, close the connection */
		close (fdi->fd);
	}
}
#endif


/* The connect_remote() call finds a remoteaddrinfo of the same ai_socktype
 * as the vlai argument; vlai is localaddrinfo but is passed as (void *) to
 * support its use in starttls_xxx as a connect_plaintext() routine.  This
 * is also the reason for the starttls_t data (that is being ignored).
 *
 * The return value is -1 on error, and errno will then be set.  Successful
 * return is a file descriptor >= 0.
 */
int connect_remote (starttls_t *curtlsdata, void *vlai) {
	struct addrinfo *lai = vlai;
	struct addrinfo *rai = remoteaddrinfo;
	while (rai) {
		if (rai->ai_socktype == lai->ai_socktype) {
			struct sockaddr_un sun;
			struct sockaddr *sai = rai->ai_addr;
			int sailen = rai->ai_addrlen;
			int sox = socket (sai->sa_family, rai->ai_socktype, rai->ai_protocol);
			if (sox == -1) {
				return -1;
			}
			if (sai->sa_family == AF_UNIX) {
				bzero (&sun, sizeof (sun));
				sun.sun_family = AF_UNIX;
				if (fmtcpy (sun.sun_path, ((struct sockaddr_un *) sai)->sun_path, sizeof (sun.sun_path), curtlsdata) != 0) {
					fprintf (stderr, "Formatted socket path too long or badly formatted: %s\n");
					close (sox);
					continue;
				}
				fprintf (stderr, "DEBUG: Formatting returned %s\n", sun.sun_path);
				sai = (struct sockaddr *) &sun;
			}
			if (connect (sox, sai, sailen) == 0) {
				return sox;
			}
			close (sox);
		}
		rai = rai->ai_next;
	}
	return -1;
}


/* The connection_thread() uses the facilities of starttls_xxx() to
 * request the plaintext fd.  It also runs chat() over the cryptfd before
 * invoking starttls_xxx(), as a preamble to the encrypted link.
 *
 * When acting as a client:
 *  - local initiator cnx is plainfd
 *  - fwd/cryptfd is constructed early, using connect_remote()
 *  - fwd/cryptfd is then subjected to chat()
 *  - fwd/cryptfd is then passed into starttls_client()
 *  - cnx/plainfd is setup in int *privdata, connect_plaintext is NULL/default
 *
 * When acting as a server:
 *  - local intitiator cnx is cryptfd
 *  - cnx/cryptfd first subjected to chat()
 *  - cnx/cryptfd is that passed into starttls_server()
 *  - fwd/plainfd is constructed on demand, in connect_plaintext()
 *  - fwd/plainfd construction is connect_remote() with privdata==localaddrinfo
 */

void *connection_thread (void *vfdi) {
	struct fdinfo *fdi = vfdi;
	int cnx = fdi->fd;
	int plainfd = -1;
	int cryptfd = -1;
	//TODO// pthread_cleanup_push (cleanup_connection, vfdi);
	printf ("Thread started to handle fd=%d\n", cnx);
	int fwd;
	int setup;
	starttls_t curtlsdata = tlsdata;	/* local working copy */

	//
	// Setup cnx/fwd and/or cryptfd/plainfd, inasfar as possible now
	if (role == 's') {
		cryptfd = cnx;
	} else {
		plainfd = cnx;
		fwd = cryptfd = connect_remote (&curtlsdata, fdi->localaddrinfo);
	}
	//
	// Perform chat on the cryptfd, as a preamble to starttls
	setup = chat (cryptfd);
	if (setup != 0) {
		fprintf (stderr, "Failed chatting precursor to TLS, error code %d\n", setup);
		return NULL;
	}
	//
	// Invoke starttls
	if (role == 's') {
		// Server: on-demand connect_remote based on localaddrinfo
		setup = starttls_server (cryptfd, &curtlsdata, fdi->localaddrinfo, connect_remote);
	} else {
		// Client: plainfd already available, default returns it
		setup = starttls_client (cryptfd, &curtlsdata, &plainfd, NULL);
	}
	if (setup == -1) {
		perror ("Failed to start TLS");
		if (plainfd >= 0) {
			close (plainfd);
			plainfd = -1;
		}
	}
	//
	// Cleanup, as the TLS Pool now connects the end points
	if (plainfd >= 0) {
		close (plainfd);
		plainfd = -1;
	}
	//TODO// pthread_cleanup_pop (1);
	return NULL;
}


int main (int argc, char *argv []) {
	int parsing = 1;
	int carrier = -1;
	int sctpdtls = 1;
	int sctpudp = 0;
	long parsed_number;
	int stream;
	int tlsfork = 0;
	char *localid = NULL;
	char *remotid = NULL;
	char *cmdsoxpath = NULL;
	struct addrinfo hint;
	struct addrinfo *localaddrinfo = NULL;
	struct addrinfo *addrwalk = NULL;
	fd_set bindings, rselect; 
	int maxbound;
	int sox = -1;
	int argc_skip;
	int cnxlim;
	struct rlimit rlimit_nofile;
	struct fdinfo *fdmem;

	//
	// Initialise variables
	tunnelcommand = argv [0];
	//
	// Fetch the limitation on the number of conncetions
	if (getrlimit (RLIMIT_NOFILE, &rlimit_nofile) == -1) {
		perror ("Failed to extract file number limit");
		exit (1);
	}
	//
	// Parse the command line arguments
	bzero (&hint, sizeof (hint));
	hint.ai_family = AF_UNSPEC;
	hint.ai_socktype = SOCK_STREAM;
	//
	// First option is either -c for client or -s for server
	//TODO// Future options may include peering
	switch (getopt (argc, argv, "cs")) {
	case 'c':
		/* -c for client */
		role = 'c';
		break;
	case 's':
		/* -s for server */
		role = 's';
		break;
	case -1:
	default:
		break;
	}
	if (role == -1) {
		fprintf (stderr, "The first argument should be -c or -s to setup a TLS client or TLS server\n");
		exit (1);
	}
	//
	// Further options are settings
	while (parsing) {
		//TODO// getlongopt
		//TODO// -d for DTLS / -D for TLS; -w for SCTP-over-UDP; -W not
		int opt = getopt (argc, argv, "udDtx:fl:r:L:R:S:C:");
		switch (opt) {
		case 'u':
			/* -u for DTLS/UDP */
			hint.ai_socktype = SOCK_DGRAM;
			fprintf (stderr, "UDP mode wrapping with DTLS is not implemented -- see man page\n");
			exit (1);
		case 'd':
			/* Run SCTP with DTLS (default) */
			sctpdtls = 1;
			break;
		case 'D':
			/* Run SCTP with TLS */
			sctpdtls = 0;
			break;
		case 'o':
			/* Run SCTP over an UDP tunnel */
			sctpudp = 1;
			break;
		case 'O':
			/* Run SCTP directly (default) */
			sctpudp = 0;
			break;
		case 't':
			/* Run over TCP (default) */
			hint.ai_socktype = SOCK_STREAM;
			break;
		case 'x':
			/* DTLS/SCTP, DTLS/SCTP/UDP, TLS/SCTP or TLS/SCTP/UDP */
			//TODO// Better to use a comma-separated list
			parsed_number = strtol (optarg, &optarg, 0);
			if (*optarg) {
				fprintf (stderr, "Syntax error in stream number to -%d\n", opt);
				exit (1);
			}
			if ((parsed_number < 0) || (parsed_number > 65535)) {
				fprintf (stderr, "Stream numbers range from 0 to 65535\n");
				exit (1);
			}
			hint.ai_socktype = SOCK_SEQPACKET;
			stream = parsed_number;
			break;
		case 'f':
			/* -f to fork TLS sessions */
			if (tlsfork) {
				fprintf (stderr, "You should only specify TLS session forking once\n");
				exit (1);
			}
			tlsfork = 1;
			break;
		case 'l':
			/* -l xxx for local  address xxx */
			parse_addrinfo (optarg, 'l', &hint, &localaddrinfo);
			break;
		case 'r':
			/* -l xxx for remote address xxx */
			parse_addrinfo (optarg, 'r', &hint, &remoteaddrinfo);
			break;
		case 'L':
			/* -L xxx for localid xxx */
			if (*tlsdata.localid) {
				fprintf (stderr, "For now, it is not permitted to specify multiple local identities\n");
				exit (1);
			}
			if (1 + strlen (optarg) > sizeof (tlsdata.localid)) {
				fprintf (stderr, "Local identity is too long\n");
				exit (1);
			}
			strcpy (tlsdata.localid, optarg);
			break;
		case 'R':
			/* -R xxx for remoteid xxx */
			if (*tlsdata.remoteid) {
				fprintf (stderr, "Cannot constrain to multiple remote identities at the same time\n");
				exit (1);
			}
			if (1 + strlen (optarg) > sizeof (tlsdata.remoteid)) {
				fprintf (stderr, "Remote identity is too long\n");
				exit (1);
			}
			strcpy (tlsdata.remoteid, optarg);
			break;
		case 'S':
			/* -S /sox/path for TLS Pool socket path /sox/path */
			if (cmdsoxpath) {
				fprintf (stderr, "You can specify only one TLS Pool command socket path\n");
				exit (1);
			}
			cmdsoxpath = strdup (optarg);
			break;
		case 'C':
			/* -C /usr/bin/chat for external chat replacement */
			if (chatcommand) {
				fprintf (stderr, "You can specify only one replacement for the ppp-style chat command\n");
				exit (1);
			}
			chatcommand = strdup (optarg);
			break;
		case -1:
			parsing = 0;
		}
	}
	//
	// Sanity checks
	if (role == -1) {
		fprintf (stderr, "Specify either -c or -s (client or server mode)\n");
		exit (1);
	}
	if (!*tlsdata.localid) {
		fprintf (stderr, "You need to specify -L (localid)\n");
		exit (1);
	}
	if (!localaddrinfo) {
		fprintf (stderr, "You need to specify -l (local socket address)\n");
		exit (1);
	}
	if (!remoteaddrinfo) {
		fprintf (stderr, "You need to specify -r (remote socket address)\n");
		exit (1);
	}
	if (cmdsoxpath) {
		if (tlspool_socket (cmdsoxpath) == -1) {
			perror ("Failed to open TLS Pool command socket");
			exit (1);
		}
	}
	tlsdata.flags = (sctpdtls? PIOF_STARTTLS_DTLS: 0);	//TODO// Later
	if (role == 'c') {
		tlsdata.flags |= PIOF_STARTTLS_SEND_SNI;
	}
	if (tlsfork) {
		tlsdata.flags |= PIOF_STARTTLS_FORK;
	}
	//
	// Allocate an information structure per file descriptor
	fdmem = malloc (sizeof (struct fdinfo [rlimit_nofile.rlim_cur]));
	if (fdmem == NULL) {
		fprintf (stderr, "Failed to allocate connection data structures\n");
		exit (1);
	}
	//
	// Collect the chatscript arguments
	global_argv = argv + (optind - 1);   /* First is arg, not progname! */
	global_argc = argc - (optind - 1);
#ifdef DEBUG
	printf ("argv_chat = %s, %s, %s... (skipped %d)\n", argv [argc_skip], argv [argc_skip+1], argv [argc_skip+1], argc_skip);
#endif
	//
	// Listen to the incoming address
	//TODO// Setup localaddrinfo/remoteaddrinfo ai_socktype as a "hint"
	//TODO// Sockets are opened in the binding loop, using localaddrinfo
	FD_ZERO (&bindings);
	maxbound = 0;
	addrwalk = localaddrinfo;
	while (addrwalk) {
		int true = 1;
		long fcntl_flags;
		int sox = socket (addrwalk->ai_family, addrwalk->ai_socktype, addrwalk->ai_protocol);
		if (sox == -1) {
			fprintf (stderr, "Failed to create socket for %s: %s\n",
					addrwalk->ai_canonname,
					strerror (errno));
			exit (1);
		}
		// Share the socket; used because the TLS Pool holds older
		// connections alive while restarting a TLS Tunnel.
		if (setsockopt (sox, SOL_SOCKET, SO_REUSEADDR, &true, sizeof (true)) != 0) {
			fprintf (stderr, "Failed to setup socket for reuse of local address (non-fatal)\n");
		}
		// Set the socket to non-blocking mode; this avoids a lockup
		// on accept() when select() reports a connection attempt that
		// is retracted before accept() is tried.
		fcntl_flags = fcntl (sox, F_GETFL, 0);
		if (fcntl_flags >= 0) {
			if (fcntl (sox, F_SETFL, fcntl_flags | O_NONBLOCK) != 0) {
				fcntl_flags = -1;
			}
		}
		if (fcntl_flags < 0) {
			fprintf (stderr, "Failed to setup for non-blocking accept()\n");
		}
		if (bind (sox, addrwalk->ai_addr, addrwalk->ai_addrlen) == -1) {
			fprintf (stderr, "Failed to bind to %s: %s\n",
					addrwalk->ai_canonname,
					strerror (errno));
			exit (1);
		}
		if (addrwalk->ai_socktype != SOCK_DGRAM) {
			if (listen (sox, 5) == -1) {
				fprintf (stderr, "Failed to listen to %s: %s\n",
						addrwalk->ai_canonname,
						strerror (errno));
				exit (1);
			}
		}
		FD_SET (sox, &bindings);
		if (sox > maxbound) {
			maxbound = sox;
		}
		addrwalk->smuggle_fd = sox; // Note: destroys ai_family info!!
		addrwalk = addrwalk->ai_next;
	}
	//
	// Fork off a daemon process
	switch (fork ()) {
	case -1:
		perror ("Failed to fork background daemon");
		exit (1);
	case 0:
		if (setsid () == (pid_t) -1) {
			perror ("Failed to create background session");
			exit (1);
		}
		break;
	default:
		printf ("DEBUG: Forked daemon process to the background\n");
		exit (0);
	}
	//
	// Handle incoming connections
	//TODO// Support simultaneous connections for real-life tunnel use
	while (1) {
		int cnx;
		rselect = bindings;
		if (select (maxbound+1, &rselect, NULL, NULL, NULL) == -1) {
			perror ("Failed to select()");
			//TODO// Is there a reason for recovery?
			exit (1);
		}
		addrwalk = localaddrinfo;
		while (addrwalk) {
			if ((addrwalk->smuggle_fd >= 0) && FD_ISSET (addrwalk->smuggle_fd, &rselect)) {
				pthread_t thr;
				if (addrwalk->ai_socktype == SOCK_DGRAM) {
					// UDP handling must be delegated
					// completely and no longer polled here
					cnx = addrwalk->smuggle_fd;
					addrwalk->smuggle_fd = -addrwalk->smuggle_fd;
				} else {
					cnx = accept (addrwalk->smuggle_fd, NULL, 0);
					if (cnx == -1) {
						// Spurious RST detected, ignore
						continue;
					}
				}
				//
				// Spark a thread to handle to connection
				fdmem [cnx].fd = cnx;
				fdmem [cnx].localaddrinfo = addrwalk;
				pthread_create (&thr, NULL, (void *) connection_thread, (void *) &fdmem [cnx]);
				pthread_detach (thr);
			}
			addrwalk = addrwalk->ai_next;
		}
	}
	exit (1);
}

