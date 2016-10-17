/* tlspool/libtlspool.c -- Library function for starttls go-get-it */

#include "whoami.h"

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <assert.h>
#include <stdint.h>
#include <limits.h>
#include <ctype.h>

#include <unistd.h>
#include <pthread.h>
#include <fcntl.h>
#include <syslog.h>

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

#if !defined(WINDOWS_PORT)
#define closesocket(s) close(s)
#endif

#ifdef WINDOWS_PORT
#define PIPE_TIMEOUT 5000
#define BUFSIZE 4096
#define random rand
#define srandom srand

#define _tprintf printf
#endif /* WINDOWS_PORT */

/* The master thread will run the receiving side of the socket that connects
 * to the TLS Pool.  The have_master_lock is used with _trylock() and will
 * succeed to lock once, thereby approving the creation of the master thread.
 */

static pthread_mutex_t have_master_lock = PTHREAD_MUTEX_INITIALIZER;

static void *master_thread (void *path);

static pool_handle_t poolfd = INVALID_POOL_HANDLE;		/* Blocked retrieval with tlspool_socket() */

static pthread_cond_t updated_poolfd = PTHREAD_COND_INITIALIZER;

static pthread_mutex_t prng_lock = PTHREAD_MUTEX_INITIALIZER;


/* Retrieve the process identity of the TLS Pool from the named file, or fall
 * back on the default file if the name is set to NULL.  Returns -1 on failure.
 */
int tlspool_pid (char *opt_pidfile) {
	int fd;
	char str_pid [256];
	char *endptr;
	size_t len;
	unsigned long pid;

	if (opt_pidfile == NULL) {
		opt_pidfile = tlspool_configvar (NULL, "daemon_pidfile");
	}
	if (opt_pidfile == NULL) {
		opt_pidfile = TLSPOOL_DEFAULT_PIDFILE_PATH;
	}
	assert (opt_pidfile != NULL);
	fd = open (opt_pidfile, O_RDONLY);
	if (fd != -1) {
		len = read (fd, str_pid, sizeof (str_pid) -1);
		close (fd);
		if ((len > 0) && (len < sizeof (str_pid))) {
			str_pid [len] = '\0';
			pid = strtoul (str_pid, &endptr, 10);
			while ((endptr != NULL) && (isspace (*endptr))) {
				endptr++;
			}
			if ((pid >= 0) && (pid <= INT_MAX) && (!*endptr)) {
				return (int) pid;
			}
		}
	}
	return -1;
}

/* The library function for starttls, which is normally called through one
 * of the two inline variations below, which start client and server sides.
 *
 * As a side effect, this routine ensures that a master thread is running
 * on the poolfd.  This is the process that actually contacts the TLS Pool
 * and sets up the poolfd socket.
 */
pool_handle_t tlspool_open_poolhandle (char *path) {
	pool_handle_t poolfdsample = poolfd;
	if (poolfdsample == INVALID_POOL_HANDLE) {
		pthread_mutex_t local_cond_wait = PTHREAD_MUTEX_INITIALIZER;
		//
		// Now that we have established a (first) poolfd, start up
		// the master thread that will recv() from it, and distribute.
		if (pthread_mutex_trylock (&have_master_lock) == 0) {
			pthread_t thr;
			unsigned int seed;
			pid_t me;
			if (!path) {
				path = tlspool_configvar (NULL, "socket_name");
			}
			if (!path) {
				path = TLSPOOL_DEFAULT_SOCKET_PATH;
			}
			assert (path != NULL);
			fprintf (stderr, "DEBUG: Opening TLS Pool on socket path %s\n", path);
#ifndef WINDOWS_PORT
			if (strlen(path) + 1 > sizeof(((struct sockaddr_un *) NULL)->sun_path)) {
				syslog(LOG_ERR, "TLS Pool path name too long for UNIX domain socket");
				exit(1);
			}
#endif
			if (pthread_create(&thr, NULL, master_thread, (void *)path) != 0) {
				syslog(LOG_NOTICE, "Failed to create TLS Pool client master thread");
				pthread_mutex_unlock(&have_master_lock);
				tlspool_close_poolhandle(poolfd);
				poolfd = INVALID_POOL_HANDLE;
				return INVALID_POOL_HANDLE;
			}
			pthread_detach (thr);
			//
			// We need enough randomness to avoid clashing ctlkeys
			me = getpid ();
			seed = ((unsigned int) time (NULL)) ^ (((unsigned int) me) << 16);
			srandom (seed);
		}
		//
		// Wait until the master thread signals that it updated the
		// poolfd, as long as it is invalid.
		//
		// The cond_wait requires a mutex to wait on; the specs leave
		// room for different mutexes for each waiter (otherwise it
		// would not have been supplied with each pthread_cond_wait()
		// call) and that helps to avoid threads to contend on a
		// shared mutex -- which is why we use a local mutex per
		// thread: we don't need to wait for unique access.
		assert (pthread_mutex_lock (&local_cond_wait) == 0);
		while (poolfdsample = poolfd, poolfdsample == INVALID_POOL_HANDLE) {
			pthread_cond_wait (&updated_poolfd, &local_cond_wait);
		}
		pthread_mutex_unlock (&local_cond_wait);
	}
	return poolfdsample;
}


/* Determine an upper limit for simultaneous STARTTLS threads, based on the
 * number of available file descriptors.  Note: The result is cached, so
 * don't use root to increase beyond max in setrlimit() after calling this.
 */
int tlspool_simultaneous_starttls(void) {
#ifdef WINDOWS_PORT
	return 512;
#else /* WINDOWS_PORT */
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
#endif /* WINDOWS_PORT */
}


/* The request registry is an array of pointers, filled by the starttls_xxx()
 * functions for as long as they have requests standing out.  The registry
 * permits instant lookup of a mutex to signal, so the receiving end may
 * pickup the message in its also-registered tlspool command buffer.
 */

struct registry_entry {
	pthread_mutex_t *sig;		/* Wait for master thread's recvmsg() */
	struct tlspool_command *buf;	/* Buffer to hold received command */
	pool_handle_t pfd;			/* Client thread's assumed poolfd */
};

static struct registry_entry **registry;

static pthread_mutex_t registry_lock = PTHREAD_MUTEX_INITIALIZER;


/* Register a request handling structure under a request ID.  Registers the
 * registry entry at the given reqid; if reqid is -1, a new one, mappable to
 * the uint16_t type for the field is allocated and set in *reqid.  When the
 * registry entry is NULL, it will be removed from the registry and the reqid
 * is reset to -1.
 *
 * The return value is 0 on success, or -1 on failure; the most probable
 * cause for failure is
 */
static int registry_update (int *reqid, struct registry_entry *entry) {
	static int simu = -1;
	static uint16_t pos = 0;
	int ctr;
	if (registry == NULL) {
		simu = tlspool_simultaneous_starttls ();
		registry = calloc (simu, sizeof (struct registry_entry *));
		if (registry == NULL) {
			syslog (LOG_NOTICE, "Failed to allocate TLS Pool request registry");
			return -1;
		}
	}
	if (entry != NULL) {
		/* Set the entry in the given entry */
		if (*reqid < 0) {
			/* Allocate an entry in the registry */
			assert (pthread_mutex_lock (&registry_lock) == 0);
			ctr = simu;
			while (ctr-- > 0) {
				if (registry [pos] == NULL) {
					registry [pos] = entry;
					*reqid = pos;
					break;
				}
				pos++;
				if (pos >= simu) {
					pos = 0;
				}
			}
			pthread_mutex_unlock (&registry_lock);
		}
		if (*reqid < 0) {
			return -1;
		}
	} else {
		if ((*reqid < 0) || (*reqid >= simu)) {
			return -1;
		}
		/* Remove the entry from the given entry */
		assert (pthread_mutex_lock (&registry_lock) == 0);
		registry [*reqid] = NULL;	/* may not be atomic */
		*reqid = -1;
		pthread_mutex_unlock (&registry_lock);
	}
	return 0;
}


/* Flush registry entries with an older poolfd value; this is used after
 * reconnecting to the TLS Pool, presumably having closed the old poolfd.
 * Any outstanding registry entries will be sent an ERROR value at this
 * time.
 */
static void registry_flush (pool_handle_t poolfd) {
	int regid = tlspool_simultaneous_starttls ();
	assert (pthread_mutex_lock (&registry_lock) == 0);
	while (regid-- > 0) {
		struct registry_entry *entry = registry [regid];
		if ((entry != NULL) && (entry->pfd != poolfd)) {
			// Fill the cmd buffer with an error message
			entry->buf->pio_cmd = PIOC_ERROR_V2;
			entry->buf->pio_data.pioc_error.tlserrno = EPIPE;
			strncpy (entry->buf->pio_data.pioc_error.message,
				"No reply from TLS Pool",
				sizeof (entry->buf->pio_data.pioc_error.message));
			// Signal continuation to the recipient
			pthread_mutex_unlock (entry->sig);
			// Do not remove the entry; the recipient will do this
		}
	}
	pthread_mutex_unlock (&registry_lock);
}

#ifdef WINDOWS_PORT
static pool_handle_t open_named_pipe (LPCTSTR lpszPipename)
{
	HANDLE hPipe;
	//struct tlspool_command chBuf;
	BOOL   fSuccess = FALSE;
	DWORD  dwMode;

	// Try to open a named pipe; wait for it, if necessary.

	while (1)
	{
		hPipe = CreateFile(
			lpszPipename,   // pipe name
			GENERIC_READ |  // read and write access
			GENERIC_WRITE,
			0,              // no sharing
			NULL,           // default security attributes
			OPEN_EXISTING,  // opens existing pipe
			FILE_FLAG_OVERLAPPED, // overlapped
			NULL);          // no template file

		// Break if the pipe handle is valid.
		if (hPipe != INVALID_POOL_HANDLE)
			break;

		// Exit if an error other than ERROR_PIPE_BUSY occurs.
		if (GetLastError() != ERROR_PIPE_BUSY)
		{
			_tprintf(TEXT("Could not open pipe. GLE=%d\n"), GetLastError());
			return INVALID_POOL_HANDLE;
		}

		// All pipe instances are busy, so wait for 20 seconds.
		if (!WaitNamedPipe(lpszPipename, 20000))
		{
			printf("Could not open pipe: 20 second wait timed out.");
			return INVALID_POOL_HANDLE;
		}
	}
	// The pipe connected; change to message-read mode.
	dwMode = PIPE_READMODE_MESSAGE;
	fSuccess = SetNamedPipeHandleState(
		hPipe,    // pipe handle
		&dwMode,  // new pipe mode
		NULL,     // don't set maximum bytes
		NULL);    // don't set maximum time
	if (!fSuccess)
	{
		_tprintf(TEXT("SetNamedPipeHandleState failed. GLE=%d\n"), GetLastError());
		return INVALID_POOL_HANDLE;
	}
	ULONG ServerProcessId;
	if (GetNamedPipeServerProcessId(hPipe, &ServerProcessId)) {
		printf("GetNamedPipeServerProcessId: ServerProcessId = %ld\n", ServerProcessId);
	} else {
		_tprintf(TEXT("GetNamedPipeServerProcessId failed. GLE=%d\n"), GetLastError());
	}
	return hPipe;
}

static int np_send_command(struct tlspool_command *cmd) {
	DWORD  cbToWrite, cbWritten;
	OVERLAPPED overlapped;
	BOOL fSuccess;

	/* Send the request */
	// Send a message to the pipe server.

	cbToWrite = sizeof (struct tlspool_command);
	_tprintf(TEXT("Sending %d byte cmd\n"), cbToWrite);

	memset(&overlapped, 0, sizeof(overlapped));
	overlapped.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);

	fSuccess = WriteFile(
		poolfd,                  // pipe handle
		cmd,                    // cmd message
		cbToWrite,              // cmd message length
		NULL,                  // bytes written
		&overlapped);            // overlapped

	if (!fSuccess && GetLastError() == ERROR_IO_PENDING )
	{
// printf ("DEBUG: Write I/O pending\n");
		fSuccess = WaitForSingleObject(overlapped.hEvent, INFINITE) == WAIT_OBJECT_0;
	}

	if (fSuccess) {
		fSuccess = GetOverlappedResult(poolfd, &overlapped, &cbWritten, TRUE);
	}

	if (!fSuccess)
	{
		_tprintf(TEXT("WriteFile to pipe failed. GLE=%d\n"), GetLastError());
		errno = EPIPE;
		return -1;
	} else {
// printf ("DEBUG: Wrote %ld bytes to pipe\n", cbWritten);
	}
// printf("DEBUG: Message sent to server, receiving reply as follows:\n");
	return 0;
}
#endif /* WINDOWS_PORT */

/* The master thread issues the recv() commands on the TLS Pool socket, and
 * redistributes the result to the registry entries that are waiting for
 * the data.  The thread is started when the poolfd is first requested.
 *
 * Having a dedicated master thread is a great design simplification over
 * temporary promotion of one of the application threads to a master status.
 * The locking involved in the distinct state without a master, and the
 * raceconditions while establishing the first on-demand master are dreadful.
 *
 * An additional advantage of a separate master thread is that it will
 * instantly notice when the TLS Pool goes offline.  At this time, it will
 * lock the registry and cancel any requests in the registry that are
 * waiting for the older connection.  Subsequent attempts to receive are
 * stopped immediately.  The TLS Pool then tries to reconnect to the
 * TLS Pool anew, using exponential back-off.
 */
static void *master_thread (void *path) {
#ifndef WINDOWS_PORT
	useconds_t usec;
	struct sockaddr_un sun;
	//NOT-USED// char anc [CMSG_SPACE(sizeof (int))];
	struct iovec iov;
	struct cmsghdr *cmsg;
	struct msghdr mh = { 0 };
#else
	DWORD usec;
#endif
	struct tlspool_command cmd;
	//NOT-USED// char anc [CMSG_SPACE(sizeof (int))];
	struct registry_entry *entry;
#ifdef WINDOWS_PORT
	BOOL   fSuccess = FALSE;
	DWORD  cbRead;
#endif

#ifndef WINDOWS_PORT
	//
	// Setup path information -- value and size were checked
	memset (&sun, 0, sizeof (sun));
	strcpy (sun.sun_path, (char *) path);
	sun.sun_family = AF_UNIX;
#endif

	//
	// Service forever
	while (1) {
		//
		// If any old socket clients persist, tell them that the
		// TLS Pool has been disconnected.
		if (poolfd != INVALID_POOL_HANDLE) {
			pool_handle_t poolfdcopy = poolfd;
// printf ("DEBUG: Removing old poolfd %d\n", poolfd);
			poolfd = INVALID_POOL_HANDLE;
			registry_flush (INVALID_POOL_HANDLE);
			tlspool_close_poolhandle (poolfdcopy);
		}
		//
		// First, connect to the TLS Pool; upon failure, retry
		// with 1s, 2s, 4s, 8s, 16s, 32s, 32s, 32s, ... intervals.
		usec = 1000000;
		while (poolfd == INVALID_POOL_HANDLE) {
#ifdef WINDOWS_PORT
// printf ("DEBUG: path = %s\n", (char *) path);
			pool_handle_t newpoolfd = open_named_pipe ((LPCTSTR) path);
// printf ("DEBUG: newpoolfd = %d\n", newpoolfd);
			if (newpoolfd != INVALID_POOL_HANDLE) {
				poolfd = newpoolfd;
			}
#else
			pool_handle_t newpoolfd = socket (AF_UNIX, SOCK_STREAM, 0);
			if (newpoolfd != INVALID_POOL_HANDLE) {
				if (connect (newpoolfd, (struct sockaddr *) &sun, SUN_LEN (&sun)) == 0) {
// printf ("DEBUG: Succeeded connect() to TLS Pool\n");
					poolfd = newpoolfd;
				} else {
					tlspool_close_poolhandle (newpoolfd);
					newpoolfd = INVALID_POOL_HANDLE;
				}
			}
// printf ("DEBUG: Trying new poolfd %d for path %s\n", poolfd, sun.sun_path);
#endif
			//
			// Signal a newly set poolfd value to all waiting.
			// Note that we do not need to claim a mutex first;
			// there is always one writer to poolfd (namely, this
			// master_thread) and the rest simply reads it.  This
			// makes a silent assumption of atomic writes to the
			// poolfd, which seems fair because the size of an
			// fd table has been smaller than the size of the
			// data bus since the times of ZX Spectrum and CP/M.
			pthread_cond_broadcast (&updated_poolfd);
// printf ("DEBUG: Signalled slave threads with poolfd %d\n", poolfd);
			//
			// Wait before repeating, with exponential back-off
			if (poolfd == INVALID_POOL_HANDLE) {
#ifdef WINDOWS_PORT
				Sleep(usec / 1000);
#else
				usleep(usec);
#endif
				usec <<= 1;
				if (usec > 32000000) {
					usec = 32000000;
				}
			}
		}
		//
		// We now have an established link to the TLS Pool, until
		// further notice -- that is, until the TLS Pool terminates.
		// At that time, a break ends the following loop and jumps
		// back up to the re-connection logic.
		while (1) {
			int retval;
#ifdef WINDOWS_PORT
			OVERLAPPED overlapped;

			memset(&overlapped, 0, sizeof(overlapped));
			overlapped.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);

			// Read from the pipe.
			fSuccess = ReadFile(
				poolfd,       // pipe handle
				&cmd,         // buffer to receive reply
				sizeof (cmd), // size of buffer
				NULL,         // number of bytes read
				&overlapped); // not overlapped

			if (!fSuccess && GetLastError() == ERROR_IO_PENDING )
			{
// printf ("DEBUG: Read I/O pending\n");
				fSuccess = WaitForSingleObject(overlapped.hEvent, INFINITE) == WAIT_OBJECT_0;
			}

			if (fSuccess) {
				fSuccess = GetOverlappedResult(poolfd, &overlapped, &cbRead, TRUE);
			}

			if (!fSuccess)
			{
				_tprintf(TEXT("ReadFile from pipe failed. GLE=%d\n"), GetLastError());
				retval = -1;
			} else {
// printf ("DEBUG: Read %ld bytes from pipe\n", cbRead);
			}
#else
			iov.iov_base = &cmd;
			iov.iov_len = sizeof (cmd);
			mh.msg_iov = &iov;
			mh.msg_iovlen = 1;
			//NOT-USED// mh.msg_control = anc;
			//NOT-USED// mh.msg_controllen = sizeof (anc);
			retval = recvmsg (poolfd, &mh, MSG_NOSIGNAL);
			if ((retval == -1) && (errno = EINTR)) {
				continue;	// Badly masked user signal
			}
			if (retval == 0) {
				errno = EPIPE;
				retval = -1;
			}
			if (retval == -1) {
				// This includes EPIPE, or EOF, for detached
				// TLS Pool; the treatment is to reconnect.
// printf ("DEBUG: recvmsg() returned -1 due to: %s\n", strerror (errno));
				break;
			}
#endif /* WINDOWS_PORT */
			//
			// Determine where to post the received message
			entry = registry [cmd.pio_reqid];
			if (entry == NULL) {
				// Protocol error!  Client detached!
// printf ("DEBUG: Client detached! poolfd=%d, cmd=0x%08x, reqid=%d, cbid=%d\n", poolfd, cmd.pio_cmd, cmd.pio_reqid, cmd.pio_cbid);
				if ((cmd.pio_cbid != 0) && (cmd.pio_cmd != PIOC_ERROR_V2)) {
// printf ("DEBUG: Will send PIOC_ERROR_V2 as callback to TLS Pool\n");
					// TLS Pool is waiting for a callback;
					// Send it an ERROR message instead.
					cmd.pio_cmd = PIOC_ERROR_V2;
					cmd.pio_data.pioc_error.tlserrno = EPIPE;
					strncpy (cmd.pio_data.pioc_error.message, "Client prematurely left TLS Pool negotiations", sizeof (cmd.pio_data.pioc_error.message));
#ifdef WINDOWS_PORT
					np_send_command (&cmd);
#else
					sendmsg (poolfd, &mh, MSG_NOSIGNAL);
#endif
					// Ignore errors
// printf ("DEBUG: Sent      PIOC_ERROR_V2 as callback to TLS Pool\n");
				}
				// Do not attempt delivery
				continue;
			}
			if (entry->pfd != poolfd) {
// printf ("DEBUG: Registry entry has older poolfd %d not %d, flushing registry\n", entry->pfd, poolfd);
				registry_flush (poolfd);
			}
			memcpy (entry->buf, &cmd, sizeof (cmd));
			//NOT-USED// deliver anc or passfd to recipient
			pthread_mutex_unlock (entry->sig);
// printf ("DEBUG: Signalled slave with new message in place\n");
		}
	}
}


/* Consider handling the message reception interface, if no other thread is
 * doing that yet.  Then, wait until a message has been received.
 */
static void registry_recvmsg (struct registry_entry *entry) {
	static pool_handle_t lastpoolfd = INVALID_POOL_HANDLE;
	//
	// Detect poolfd socket change for potential dangling recipients
	if (entry->pfd != lastpoolfd) {
		lastpoolfd = tlspool_open_poolhandle (NULL);
		if ((entry->pfd != lastpoolfd) && (lastpoolfd != INVALID_POOL_HANDLE)) {
			// Signal PIOC_ERROR to outdated recipients.
			// (That will include the current recipient.)
			registry_flush (lastpoolfd);
		}
	}
	//
	// Now wait for the registered command structure to be filled
	// by the master thread.  Note that the call to tlspool_open_poolhandle()
	// above is made when this function is first called, and that
	// routine ensures running of the master thread.
	assert (pthread_mutex_lock (entry->sig) == 0);
}


/* The library function for ping, which is called to establish the API
 * version and a list of facilities supported by the TLS Pool.  The data
 * supplied to the TLS Pool should represent the environment of the
 * application, which is why no defaults are provided by this function
 * but the application should supply all ping data.
 *
 * The pioc_ping structure will be copied into the command structure,
 * and upon completion it will be copied back.  Normally, the application
 * would set YYYYMMDD_producer to TLSPOOL_IDENTITY_V2, and facilities
 * to PIOF_FACILITY_ALL_CURRENT.  The TLS Pool overwrites the former and
 * resets unsupported bits in the latter.  Note that facilities may be
 * unsupported due to the compile-time environment of the TLS Pool or
 * because it was configured without the requested support.
 *
 * This function returns zero on success, and -1 on failure.  In case of
 * failure, errno will be set.
 */
int tlspool_ping (pingpool_t *pingdata) {
	struct tlspool_command cmd;
	pthread_mutex_t recvwait = PTHREAD_MUTEX_INITIALIZER;
	struct registry_entry regent = { .sig = &recvwait, .buf = &cmd };
	int entry_reqid = -1;
	pool_handle_t poolfd = INVALID_POOL_HANDLE;

	/* Prepare command structure */
	poolfd = tlspool_open_poolhandle (NULL);
// printf ("DEBUG: poolfd = %d\n", poolfd);
	if (poolfd == INVALID_POOL_HANDLE) {
		errno = ENODEV;
		return -1;
	}
	/* Finish setting up the registry entry */
	regent.pfd = poolfd;
	pthread_mutex_lock (&recvwait);		// Will await unlock by master
	/* Determine the request ID */
	if (registry_update (&entry_reqid, &regent) != 0) {
		errno = EBUSY;
		return -1;
	}
	memset (&cmd, 0, sizeof (cmd));	/* Do not leak old stack info */
	cmd.pio_reqid = entry_reqid;
	cmd.pio_cbid = 0;
	cmd.pio_cmd = PIOC_PING_V2;
	memcpy (&cmd.pio_data.pioc_ping, pingdata, sizeof (struct pioc_ping));
#ifdef WINDOWS_PORT
	if (np_send_command (&cmd) == -1) {
		// errno inherited from np_send_command ()
		registry_update (&entry_reqid, NULL);
		return -1;
	}
#else
	/* Send the request */
	if (send (poolfd, &cmd, sizeof (cmd), MSG_NOSIGNAL) == -1) {
		// Let SIGPIPE be reported as EPIPE
		registry_update (&entry_reqid, NULL);
		// errno inherited from sendmsg()
		return -1;
	}
#endif
	/* Await response and process it */
	registry_recvmsg (&regent);
	registry_update (&entry_reqid, NULL);
	switch (cmd.pio_cmd) {
	case PIOC_ERROR_V2:
		/* Bad luck, we failed */
		syslog (LOG_INFO, "TLS Pool error to tlspool_ping(): %s", cmd.pio_data.pioc_error.message);
		errno = cmd.pio_data.pioc_error.tlserrno;
		return -1;
	case PIOC_PING_V2:
		/* Wheee!!! we're done */
		memcpy (pingdata, &cmd.pio_data.pioc_ping, sizeof (pingpool_t));
		return 0;
	default:
		/* V2 protocol error */
		errno = EPROTO;
		return -1;
	}
}

#if defined(WINDOWS_PORT)
static int socket_dup_protocol_info(int fd, int pid, LPWSAPROTOCOL_INFOW lpProtocolInfo)
{
	if (WSADuplicateSocketW((SOCKET)fd, pid, lpProtocolInfo) == SOCKET_ERROR) {
		errno = EPIPE;
		return -1;
	} else {
		return 0;
	}	
}
#endif

/* The library function for starttls, which is normally called through one
 * of the two inline variations below, which start client and server sides.
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
int tlspool_starttls (int cryptfd, starttls_t *tlsdata,
			void *privdata,
			int (*namedconnect) (starttls_t *tlsdata,void *privdata)) {
	struct tlspool_command cmd;
	pthread_mutex_t recvwait = PTHREAD_MUTEX_INITIALIZER;
	struct registry_entry regent = { .sig = &recvwait, .buf = &cmd };
	int entry_reqid = -1;
	pool_handle_t poolfd = INVALID_POOL_HANDLE;
	int plainfd = -1;
	int sentfd = -1;
#ifndef WINDOWS_PORT
	struct iovec iov;
	struct cmsghdr *cmsg;
	struct msghdr mh = { 0 };
	char anc[CMSG_SPACE(sizeof(int))];
#endif
	int processing;
	int renegotiate = 0 != (tlsdata->flags & PIOF_STARTTLS_RENEGOTIATE);

	/* Prepare command structure */
	poolfd = tlspool_open_poolhandle (NULL);
	if (poolfd == INVALID_POOL_HANDLE) {
		closesocket(cryptfd);
		errno = ENODEV;
		return -1;
	}
	/* Finish setting up the registry entry */
	regent.pfd = poolfd;
	pthread_mutex_lock (&recvwait);		// Will await unlock by master
	/* Determine the request ID */
	if (registry_update (&entry_reqid, &regent) != 0) {
		closesocket(cryptfd);
		errno = EBUSY;
		return -1;
	}
	memset (&cmd, 0, sizeof (cmd));	/* Do not leak old stack info */
	cmd.pio_reqid = entry_reqid;
	cmd.pio_cbid = 0;
	cmd.pio_cmd = PIOC_STARTTLS_V2;
	memcpy (&cmd.pio_data.pioc_starttls, tlsdata, sizeof (struct pioc_starttls));

#if TLSPOOL_CTLKEYLEN != 16
#  error "Failure on assumption of 16 bytes per ctlkey"
#endif

	if (!renegotiate) {
		assert (pthread_mutex_lock (&prng_lock) == 0);
#if RAND_MAX >= 0xffffffff
		* (uint32_t *) &cmd.pio_data.pioc_starttls.ctlkey [ 0] = random ();
		* (uint32_t *) &cmd.pio_data.pioc_starttls.ctlkey [ 4] = random ();
		* (uint32_t *) &cmd.pio_data.pioc_starttls.ctlkey [ 8] = random ();
		* (uint32_t *) &cmd.pio_data.pioc_starttls.ctlkey [12] = random ();
#elif RAND_MAX >= 0xffff
		* (uint16_t *) &cmd.pio_data.pioc_starttls.ctlkey [ 0] = random ();
		* (uint16_t *) &cmd.pio_data.pioc_starttls.ctlkey [ 2] = random ();
		* (uint16_t *) &cmd.pio_data.pioc_starttls.ctlkey [ 4] = random ();
		* (uint16_t *) &cmd.pio_data.pioc_starttls.ctlkey [ 6] = random ();
		* (uint16_t *) &cmd.pio_data.pioc_starttls.ctlkey [ 8] = random ();
		* (uint16_t *) &cmd.pio_data.pioc_starttls.ctlkey [10] = random ();
		* (uint16_t *) &cmd.pio_data.pioc_starttls.ctlkey [12] = random ();
		* (uint16_t *) &cmd.pio_data.pioc_starttls.ctlkey [14] = random ();
#elif RAND_MAX >= 0xff
		* (uint8_t *) &cmd.pio_data.pioc_starttls.ctlkey [ 0] = random ();
		* (uint8_t *) &cmd.pio_data.pioc_starttls.ctlkey [ 1] = random ();
		* (uint8_t *) &cmd.pio_data.pioc_starttls.ctlkey [ 2] = random ();
		* (uint8_t *) &cmd.pio_data.pioc_starttls.ctlkey [ 3] = random ();
		* (uint8_t *) &cmd.pio_data.pioc_starttls.ctlkey [ 4] = random ();
		* (uint8_t *) &cmd.pio_data.pioc_starttls.ctlkey [ 5] = random ();
		* (uint8_t *) &cmd.pio_data.pioc_starttls.ctlkey [ 6] = random ();
		* (uint8_t *) &cmd.pio_data.pioc_starttls.ctlkey [ 7] = random ();
		* (uint8_t *) &cmd.pio_data.pioc_starttls.ctlkey [ 8] = random ();
		* (uint8_t *) &cmd.pio_data.pioc_starttls.ctlkey [ 9] = random ();
		* (uint8_t *) &cmd.pio_data.pioc_starttls.ctlkey [10] = random ();
		* (uint8_t *) &cmd.pio_data.pioc_starttls.ctlkey [11] = random ();
		* (uint8_t *) &cmd.pio_data.pioc_starttls.ctlkey [12] = random ();
		* (uint8_t *) &cmd.pio_data.pioc_starttls.ctlkey [13] = random ();
		* (uint8_t *) &cmd.pio_data.pioc_starttls.ctlkey [14] = random ();
		* (uint8_t *) &cmd.pio_data.pioc_starttls.ctlkey [15] = random ();
#else
#  error "Unsuitable random() function due to RAND_MAX value < 0xff"
#endif
		pthread_mutex_unlock (&prng_lock);
	}
// printf ("DEBUG: ctlkey =");
// {int i; for (i=0;i<16;i++) printf (" %02x", cmd.pio_data.pioc_starttls.ctlkey [i]);}
// printf ("\n");

	/* Send the request */
#ifndef WINDOWS_PORT
	iov.iov_base = &cmd;
	iov.iov_len = sizeof(cmd);
	mh.msg_iov = &iov;
	mh.msg_iovlen = 1;
#endif
	if (!renegotiate) {
#ifndef WINDOWS_PORT
		mh.msg_control = anc;
		mh.msg_controllen = sizeof (anc);
		cmsg = CMSG_FIRSTHDR (&mh);
		cmsg->cmsg_level = SOL_SOCKET;
		cmsg->cmsg_type = SCM_RIGHTS;
		*(int *)CMSG_DATA(cmsg) = cryptfd;	/* cannot close it yet */
		cmsg->cmsg_len = CMSG_LEN(sizeof(int));
#else /* WINDOWS_PORT */
		// cmd was already set to 0, including ancilary data simulation
		if (1 /*is_sock(wsock)*/) {
			// Send a socket
			LONG pid;

			GetNamedPipeServerProcessId(poolfd, &pid);
			cmd.pio_ancil_type = ANCIL_TYPE_SOCKET;
			printf("DEBUG: pid = %d, cryptfd = %d\n", pid, cryptfd);
			if (socket_dup_protocol_info(cryptfd, pid, &cmd.pio_ancil_data.pioa_socket) == -1) {
				// printf("DEBUG: cygwin_socket_dup_protocol_info error\n");
				// Let SIGPIPE be reported as EPIPE
				closesocket(cryptfd);
				registry_update (&entry_reqid, NULL);
				// errno inherited from socket_dup_protocol_info()
				return -1;
			}
			//... (..., &cmd.pio_ancil_data.pioa_socket, ...);
		} else {
			// Send a file handle
			cmd.pio_ancil_type = ANCIL_TYPE_FILEHANDLE;
			//... (..., &cmd.pio_ancil_data.pioa_filehandle, ...);
		}
#endif /* WINDOWS_PORT */
	}
#ifdef WINDOWS_PORT
	if (np_send_command (&cmd) == -1) {
		close (cryptfd);
		registry_update (&entry_reqid, NULL);
		// errno inherited from np_send_command ()
		return -1;
	}
#else
	if (sendmsg (poolfd, &mh, MSG_NOSIGNAL) == -1) {
		// Let SIGPIPE be reported as EPIPE
		close (cryptfd);
		registry_update (&entry_reqid, NULL);
		// errno inherited from sendmsg()
		return -1;
	}
#endif /* WINDOWS_PORT */
	sentfd = cryptfd;  /* Close anytime after response and before fn end */

	/* Handle responses until success or error */
	processing = 1;
	while (processing) {
		//NOTUSED// mh.msg_control = anc;
		//NOTUSED// mh.msg_controllen = sizeof (anc);
		registry_recvmsg (&regent);
		if (sentfd >= 0) {
			closesocket(sentfd);
		}
		sentfd = -1;
		switch (cmd.pio_cmd) {
		case PIOC_ERROR_V2:
			/* Bad luck, we failed */
			syslog (LOG_INFO, "TLS Pool error to tlspool_starttls(): %s", cmd.pio_data.pioc_error.message);
			registry_update (&entry_reqid, NULL);
			errno = cmd.pio_data.pioc_error.tlserrno;
			return -1;
		case PIOC_STARTTLS_LOCALID_V2:
		case PIOC_PLAINTEXT_CONNECT_V2:
			if (namedconnect) {
				plainfd = (*namedconnect) (tlsdata, privdata);
			} else {
				/* default namedconnect() implementation */
				plainfd = * (int *) privdata;
				if ((plainfd < 0) && (cmd.pio_cmd == PIOC_PLAINTEXT_CONNECT_V2)) {
#if !defined(WINDOWS_PORT)
					int soxx[2];
#else
					// https://github.com/ncm/selectable-socketpair
					extern int dumb_socketpair(SOCKET socks[2], int make_overlapped);
					SOCKET soxx[2];
#endif
					//TODO// Setup for TCP, UDP, SCTP
#ifndef WINDOWS_PORT
					if (socketpair (AF_UNIX, SOCK_SEQPACKET, 0, soxx) == 0) {
#else /* WINDOWS_PORT */
					if (dumb_socketpair(soxx, 1) == 0) {
#endif /* WINDOWS_PORT */
						// printf("DEBUG: socketpair succeeded\n");
						/* Socketpair created */
						plainfd = soxx [0];
						* (int *) privdata = soxx [1];
					} else {
						/* Socketpair failed */
						// printf("DEBUG: socketpair failed\n");
						cmd.pio_cmd = PIOC_ERROR_V2;
						cmd.pio_data.pioc_error.tlserrno = errno;
						plainfd = -1;
					}
				}
			}
			/* We may now have a value to send in plainfd */
			if (plainfd >= 0) {
#ifndef WINDOWS_PORT
				mh.msg_control = anc;
				mh.msg_controllen = sizeof (anc);
				cmsg = CMSG_FIRSTHDR (&mh);
				cmsg->cmsg_level = SOL_SOCKET;
				cmsg->cmsg_type = SCM_RIGHTS;
				* (int *) CMSG_DATA (cmsg) = plainfd;
				cmsg->cmsg_len = CMSG_LEN (sizeof (int));
#else /* ifdef WINDOWS_PORT */
				// cmd was already set to 0, including ancilary data simulation
				if (1 /*is_sock(wsock)*/) {
					// Send a socket
					ULONG pid;
					GetNamedPipeServerProcessId(poolfd, &pid);
					cmd.pio_ancil_type = ANCIL_TYPE_SOCKET;
					// printf("DEBUG: pid = %d, plainfd = %d\n", pid, plainfd);
					if (socket_dup_protocol_info(plainfd, pid, &cmd.pio_ancil_data.pioa_socket) == -1) {
						// printf("DEBUG: cygwin_socket_dup_protocol_info error\n");
						// Let SIGPIPE be reported as EPIPE
						closesocket(plainfd);
						registry_update (&entry_reqid, NULL);
						// errno inherited from socket_dup_protocol_info()
						return -1;
					}
					//... (..., &cmd.pio_ancil_data.pioa_socket, ...);
				} else {
					// Send a file handle
					cmd.pio_ancil_type = ANCIL_TYPE_FILEHANDLE;
					//... (..., &cmd.pio_ancil_data.pioa_filehandle, ...);
				}
#endif /* WINDOWS_PORT */
			}

			/* Now supply plainfd in the callback response */
			sentfd = plainfd;
#ifdef WINDOWS_PORT
			if (np_send_command (&cmd) == -1) {
				if (sentfd >= 0) {
					closesocket(sentfd);
					sentfd = -1;
				}
				registry_update (&entry_reqid, NULL);
				// errno inherited from np_send_command()
				return -1;
			}
#else
			if (sendmsg (poolfd, &mh, MSG_NOSIGNAL) == -1) {
				// Let SIGPIPE be reported as EPIPE
				if (sentfd >= 0) {
					close (sentfd);
					sentfd = -1;
				}
				registry_update (&entry_reqid, NULL);
				// errno inherited from sendmsg()
				return -1;
			}
#endif /* WINDOWS_PORT */
			break;	// Loop around and try again
		case PIOC_STARTTLS_V2:
			/* Wheee!!! we're done */
			processing = 0;
			break;
		default:
			/* V2 protocol error */
			registry_update (&entry_reqid, NULL);
			errno = EPROTO;
			return -1;
		}
	}

	/* Close the now-duplicated or now-erradicated plaintext fd */

	memcpy (tlsdata, &cmd.pio_data.pioc_starttls, sizeof (struct pioc_starttls));
// printf ("DEBUG: Returning control key %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\n", tlsdata->ctlkey [0], tlsdata->ctlkey [1], tlsdata->ctlkey [2], tlsdata->ctlkey [3], tlsdata->ctlkey [4], tlsdata->ctlkey [5], tlsdata->ctlkey [6], tlsdata->ctlkey [7], tlsdata->ctlkey [8], tlsdata->ctlkey [9], tlsdata->ctlkey [10], tlsdata->ctlkey [11], tlsdata->ctlkey [12], tlsdata->ctlkey [13], tlsdata->ctlkey [14], tlsdata->ctlkey [15]);
	registry_update (&entry_reqid, NULL);
	return 0;
}


/* The library function to send a control connection command, notably
 * TLSPOOL_CONTROL_DETACH and TLSPOOL_CONTROL_REATTACH.
 *
 * This function returns zero on success, and -1 on failure.  In case of
 * failure, errno will be set.
 */
int _tlspool_control_command (int cmdcode, uint8_t *ctlkey) {
	struct tlspool_command cmd;
	pthread_mutex_t recvwait = PTHREAD_MUTEX_INITIALIZER;
	struct registry_entry regent = { .sig = &recvwait, .buf = &cmd };
	int entry_reqid = -1;
	int retval;

	/* Prepare command structure */
	poolfd = tlspool_open_poolhandle (NULL);
	if (poolfd == INVALID_POOL_HANDLE) {
		errno = ENODEV;
		return -1;
	}
	/* Finish setting up the registry entry */
	regent.pfd = poolfd;
	pthread_mutex_lock (&recvwait);		// Will await unlock by master
	/* Determine the request ID */
	if (registry_update (&entry_reqid, &regent) != 0) {
		errno = EBUSY;
		return -1;
	}
	memset (&cmd, 0, sizeof (cmd));	/* Do not leak old stack info */
	cmd.pio_reqid = entry_reqid;
	cmd.pio_cbid = 0;
	cmd.pio_cmd = cmdcode;
	memcpy (&cmd.pio_data.pioc_control.ctlkey, ctlkey, TLSPOOL_CTLKEYLEN);
// printf ("DEBUG: Using control key %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\n", cmd.pio_data.pioc_control.ctlkey [0], cmd.pio_data.pioc_control.ctlkey [1], cmd.pio_data.pioc_control.ctlkey [2], cmd.pio_data.pioc_control.ctlkey [3], cmd.pio_data.pioc_control.ctlkey [4], cmd.pio_data.pioc_control.ctlkey [5], cmd.pio_data.pioc_control.ctlkey [6], cmd.pio_data.pioc_control.ctlkey [7], cmd.pio_data.pioc_control.ctlkey [8], cmd.pio_data.pioc_control.ctlkey [9], cmd.pio_data.pioc_control.ctlkey [10], cmd.pio_data.pioc_control.ctlkey [11], cmd.pio_data.pioc_control.ctlkey [12], cmd.pio_data.pioc_control.ctlkey [13], cmd.pio_data.pioc_control.ctlkey [14], cmd.pio_data.pioc_control.ctlkey [15]);

#ifdef WINDOWS_PORT
	if (np_send_command (&cmd) == -1) {
		registry_update (&entry_reqid, NULL);
		// errno inherited from np_send_command ()
		return -1;
	}
#else
	/* Send the request */
	if (send (poolfd, &cmd, sizeof (cmd), MSG_NOSIGNAL) == -1) {
		// Let SIGPIPE be reported as EPIPE
		registry_update (&entry_reqid, NULL);
		// errno inherited from send()
		return -1;
	}
#endif
	/* Receive the response */
	registry_recvmsg (&regent);
	switch (cmd.pio_cmd) {
	case PIOC_SUCCESS_V2:
		retval = 0;
		break;
	case PIOC_ERROR_V2:
		retval = -1;
		errno = cmd.pio_data.pioc_error.tlserrno;
		break;
	default:
		errno = EPROTO;
		retval = -1;
		break;
	}
	return retval;
}

/* Generate a pseudo-random sequence based on session cryptographic keys.
 *
 * In the case of TLS, this adheres to RFC 5705; other protocols may or
 * may not support a similar mechanism, in which case an error is returned.
 *
 * This leans on access privileges to an existing connection at a meta-level,
 * for which we use the customary ctlkey verification mechanism introduced with
 * tlspool_starttls ().  Note that random material may be used for security
 * purposes, such as finding the same session key for both sides deriving from
 * prior key negotiation; the protection of a ctlkey for such applications is
 * important.
 *
 * The inputs to this function must adhere to the following restrictions:
 *  - label must not be a NULL pointer, but opt_ctxvalue may be set to NULL
 *    to bypass the use of a context value.  Note that passing an empty string
 *    in opt_ctxvalue is different from not providing the string at all by
 *    setting it to NULL.
 *  - label  and  opt_ctxvalue  (if non-NULL) refer to ASCII strings with
 *    printable characters, terminated with a NUL character.  The maximum
 *    string length of each is 254 bytes.
 *  - prng_len holds the requested number of pseudo-random bytes
 *  - prng_buf points is a non-NULL pointer to a buffer that can hold
 *    prng_len bytes.
 *
 * If the operation succeeds, then prng_buf holds prng_len bytes of random
 * material, and zero is returned.  If the operation fails, then prng_buf
 * is filled with zero bytes (to make it stand out as a rather rare case of
 * a random byte string) and -1 is returned.
 *
 * Note a few restrictions to the generality of this function, as a result of
 * the underlying packet format for the communication with the TLS Pool; but
 * the dimensions have been choosen such that these restrictions would not
 * typically be a problem in practice:
 *  - it constrains the string lengths of label and opt_ctxvalue
 *  - it constrains prng_len to a maximum value of TLSPOOL_PRNGBUFLEN
 *
 * The TLS Pool may limit certain TLS PRNG labels, in adherence to the
 * IANA-maintained TLS Exporter Label Registry.  It additionally supports
 * the EXPERIMENTAL label prefix specified in RFC 5705.
 *
 * Be advised that the maximum size of buffer may increase in future releases.
 * So, be sure to use TLSPOOL_PRNGBUFLEN which holds the header-file defined
 * size.
 */
int tlspool_prng (char *label, char *opt_ctxvalue,
		uint16_t prng_len, uint8_t *prng_buf,
		uint8_t *ctlkey) {
	struct tlspool_command cmd;
	pthread_mutex_t recvwait = PTHREAD_MUTEX_INITIALIZER;
	struct registry_entry regent = { .sig = &recvwait, .buf = &cmd };
	int entry_reqid = -1;
	pool_handle_t poolfd = INVALID_POOL_HANDLE;
	memset (prng_buf, 0, prng_len);

	/* Sanity checks */
	if ((prng_len > TLSPOOL_PRNGBUFLEN) ||
			(label == NULL) || (strlen (label) > 254) ||
			((opt_ctxvalue != NULL) &&
				((strlen (opt_ctxvalue) > 254) ||
					(strlen (label) + strlen (opt_ctxvalue) > TLSPOOL_PRNGBUFLEN - TLSPOOL_CTLKEYLEN)))) {
		errno = EINVAL;
		return -1;
	}


	/* Prepare command structure */
	poolfd = tlspool_open_poolhandle (NULL);
	if (poolfd == INVALID_POOL_HANDLE) {
		errno = ENODEV;
		return -1;
	}
	/* Finish setting up the registry entry */
	regent.pfd = poolfd;
	pthread_mutex_lock (&recvwait);		// Will await unlock by master
	/* Determine the request ID */
	if (registry_update (&entry_reqid, &regent) != 0) {
		errno = EBUSY;
		return -1;
	}
	memset (&cmd, 0, sizeof (cmd));	/* Do not leak old stack info */
	cmd.pio_reqid = entry_reqid;
	cmd.pio_cbid = 0;
	cmd.pio_cmd = PIOC_PRNG_V2;
	cmd.pio_data.pioc_prng.prng_len = prng_len;
	memcpy (cmd.pio_data.pioc_prng.buffer, ctlkey, TLSPOOL_CTLKEYLEN);
	cmd.pio_data.pioc_prng.in1_len = strlen (label);
	memcpy (cmd.pio_data.pioc_prng.buffer + TLSPOOL_CTLKEYLEN, label, cmd.pio_data.pioc_prng.in1_len);
	if (opt_ctxvalue != NULL) {
		cmd.pio_data.pioc_prng.in2_len = strlen (opt_ctxvalue);
		memcpy (cmd.pio_data.pioc_prng.buffer + TLSPOOL_CTLKEYLEN + cmd.pio_data.pioc_prng.in1_len, opt_ctxvalue, cmd.pio_data.pioc_prng.in2_len);
	} else {
		cmd.pio_data.pioc_prng.in2_len = -1;
	}

#ifdef WINDOWS_PORT
if (np_send_command (&cmd) == -1) {
	// errno inherited from np_send_command ()
	registry_update (&entry_reqid, NULL);
	return -1;
}
#else
	/* Send the request */
	if (send (poolfd, &cmd, sizeof (cmd), MSG_NOSIGNAL) == -1) {
		// Let SIGPIPE be reported as EPIPE
		registry_update (&entry_reqid, NULL);
		// errno inherited from sendmsg()
		return -1;
	}
#endif
	/* Await response and process it */
	registry_recvmsg (&regent);
	registry_update (&entry_reqid, NULL);
	switch (cmd.pio_cmd) {
	case PIOC_ERROR_V2:
		/* Bad luck, we failed */
		syslog (LOG_INFO, "TLS Pool error to tlspool_ping(): %s", cmd.pio_data.pioc_error.message);
		errno = cmd.pio_data.pioc_error.tlserrno;
		return -1;
	case PIOC_PRNG_V2:
		/* Wheee!!! we're done */
		memcpy (prng_buf, cmd.pio_data.pioc_prng.buffer, prng_len);
		return 0;
	default:
		/* V2 protocol error */
		errno = EPROTO;
		return -1;
	}
}

