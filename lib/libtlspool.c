/* tlspool/libtlspool.c -- Library function for starttls go-get-it */

#include "whoami.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <stdint.h>
#include <limits.h>
#include <ctype.h>

#include <errno.h>
#include <com_err.h>
#include <errortable.h>

#include <pthread.h>
#include <fcntl.h>
#include <syslog.h>

#include <tlspool/starttls.h>
#include <tlspool/commands.h>

#ifndef WINDOWS_PORT
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/select.h>
#include <sys/resource.h>
#include <netinet/in.h>
#endif

#if !defined(WINDOWS_PORT)
#define closesocket(s) close(s)
#endif

#ifdef WINDOWS_PORT
#define random rand
#define srandom srand
#define _tprintf printf
#endif /* WINDOWS_PORT */

/* Windows supports SCTP but fails to define this IANA-standardised symbol: */
#ifndef IPPROTO_SCTP
#define IPPROTO_SCTP 132
#endif

#ifdef WINDOWS_PORT
#include "libtlspool_windows.c"
#else
#include "libtlspool_posix.c"
#endif

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

	if (opt_pidfile == NULL) {
		opt_pidfile = tlspool_configvar (NULL, "daemon_pidfile");
	}
	if (opt_pidfile == NULL) {
		opt_pidfile = TLSPOOL_DEFAULT_PIDFILE_PATH;
	}
	assert (opt_pidfile != NULL);
	fd = open (opt_pidfile, O_RDONLY);
	if (fd != -1) {
		size_t len = read (fd, str_pid, sizeof (str_pid) -1);
		close (fd);
		if ((len > 0) && (len < sizeof (str_pid))) {
			str_pid [len] = '\0';
			/* pid_t */ unsigned long pid = strtoul (str_pid, &endptr, 10);
			while ((endptr != NULL) && (isspace (*endptr))) {
				endptr++;
			}
			if ((pid <= INT_MAX) && (!*endptr)) {
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
			entry->buf->pio_data.pioc_error.tlserrno = E_TLSPOOL_CLIENT_DISCONNECT;
			strncpy (entry->buf->pio_data.pioc_error.message,
				"TLS Pool connection closed",
				sizeof (entry->buf->pio_data.pioc_error.message));
			// Signal continuation to the recipient
			pthread_mutex_unlock (entry->sig);
			// Do not remove the entry; the recipient will do this
		}
	}
	pthread_mutex_unlock (&registry_lock);
}

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
	unsigned int usec;
	struct tlspool_command cmd;
	//NOT-USED// char anc [CMSG_SPACE(sizeof (int))];
	struct registry_entry *entry;


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
			pool_handle_t newpoolfd = open_pool (path);			
			if (newpoolfd != INVALID_POOL_HANDLE) {
				poolfd = newpoolfd;
			}
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
				os_usleep(usec);
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
			int retval = os_recvmsg_command(poolfd, &cmd);
#ifndef WINDOWS_PORT
			if ((retval == -1) && (errno = EINTR)) {
				continue;	// Badly masked user signal
			}
			if (retval == 0) {
				errno = EPIPE;
				retval = -1;
			}
#endif /* !WINDOWS_PORT */
			if (retval == -1) {
				// This includes EPIPE, or EOF, for detached
				// TLS Pool; the treatment is to reconnect.
// printf ("DEBUG: recvmsg() returned -1 due to: %s\n", strerror (errno));
				break;
			}
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
					cmd.pio_data.pioc_error.tlserrno = E_TLSPOOL_CLIENT_REFUSES_CALLBACK;
					strncpy (cmd.pio_data.pioc_error.message,
							"TLS Pool client will not partake in callback",
							sizeof (cmd.pio_data.pioc_error.message));
					os_sendmsg_command (poolfd, &cmd, -1);
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
	if (os_sendmsg_command (poolfd, &cmd, -1) == -1) {
		// Let SIGPIPE be reported as EPIPE
		registry_update (&entry_reqid, NULL);
		// errno inherited from sendmsg()
		return -1;
	}
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
	int processing;
	int renegotiate = 0 != (tlsdata->flags & PIOF_STARTTLS_RENEGOTIATE);
	int type = ipproto_to_sockettype (tlsdata->ipproto);
	if (type == -1) {
		errno = EINVAL;
		return -1;
	}
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
	os_sendmsg_command(poolfd, &cmd, renegotiate ? -1 : cryptfd);
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
				fprintf (stderr, "Callback to check local id or provide plaintext fd for localid=%s\n", cmd.pio_data.pioc_starttls.localid);
				plainfd = (*namedconnect) (&cmd.pio_data.pioc_starttls, privdata);
			} else {
				/* default namedconnect() implementation */
				plainfd = * (int *) privdata;
				if ((plainfd < 0) && (cmd.pio_cmd == PIOC_PLAINTEXT_CONNECT_V2)) {
					plainfd = tlspool_namedconnect_default (&cmd.pio_data.pioc_starttls, privdata);
				}
			}
			if (plainfd == -1) {
				cmd.pio_cmd = PIOC_ERROR_V2;
				cmd.pio_data.pioc_error.tlserrno = errno;
			}
			/* We may now have a value to send in plainfd */
			/* Now supply plainfd in the callback response */
			sentfd = plainfd;
			os_sendmsg_command(poolfd, &cmd, plainfd);
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
	if (os_sendmsg_command (poolfd, &cmd, -1) == -1) {
		// Let SIGPIPE be reported as EPIPE
		registry_update (&entry_reqid, NULL);
		// errno inherited from os_sendmsg_command()
		return -1;
	}
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
int tlspool_prng (char *label,
		uint16_t ctxvalue_len, uint8_t *opt_ctxvalue,
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
				((ctxvalue_len > 254) ||
					(strlen (label) + ctxvalue_len > TLSPOOL_PRNGBUFLEN - TLSPOOL_CTLKEYLEN)))) {
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
		cmd.pio_data.pioc_prng.in2_len = ctxvalue_len;
		memcpy (cmd.pio_data.pioc_prng.buffer + TLSPOOL_CTLKEYLEN + cmd.pio_data.pioc_prng.in1_len, opt_ctxvalue, cmd.pio_data.pioc_prng.in2_len);
	} else {
		cmd.pio_data.pioc_prng.in2_len = -1;
	}
	if (os_sendmsg_command (poolfd, &cmd, -1) == -1) {
		// Let SIGPIPE be reported as EPIPE
		registry_update (&entry_reqid, NULL);
		// errno inherited from sendmsg()
		return -1;
	}
	/* Await response and process it */
	registry_recvmsg (&regent);
	registry_update (&entry_reqid, NULL);
	switch (cmd.pio_cmd) {
	case PIOC_ERROR_V2:
		/* Bad luck, we failed */
		syslog (LOG_INFO, "TLS Pool error to tlspool_prng(): %s", cmd.pio_data.pioc_error.message);
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

/* Check or retrieve information from the TLS Pool.  Use kind_info to select
 * the kind of information, with a PIOK_INFO_xxx tag from <tlspool/commands.h>.
 *
 * The amount of data will not exceed TLSPOOL_INFOBUFLEN, and you should
 * provide a buffer that can hold at least that number of bytes.  In addition,
 * you should provide a pointer to a length.  Initialise this length to ~0
 * to perform a query.  Any other length indicates a match, including the
 * value 0 for a match with an empty string.
 *
 * You should provide the ctlkey from the tlspool_starttls() exchange to
 * be able to reference the connection that you intend to query.
 *
 * This function returns zero on success, and -1 on failure.  In case of
 * failure, errno will be set.  Specifically useful to know is that errno
 * is set to E_TLSPOOL_INFOKIND_UNKNOWN when the TLS Pool has no code to
 * provide the requested information (and so its current version will not
 * provide it to any query) and to E_TLSPOOL_INFO_NOT_FOUND when the
 * TLS Pool cannot answer the info query for other reasons, such as not
 * having the information available in the current connection.
 * 
 * The error ENOSYS is returned when the TLS Pool has no implementation
 * for the query you made.
 */
int tlspool_info (uint32_t info_kind,
			uint8_t infobuf [TLSPOOL_INFOBUFLEN], uint16_t *infolenptr,
			uint8_t *ctlkey) {
	struct tlspool_command cmd;
	pthread_mutex_t recvwait = PTHREAD_MUTEX_INITIALIZER;
	struct registry_entry regent = { .sig = &recvwait, .buf = &cmd };
	int entry_reqid = -1;
	pool_handle_t poolfd = INVALID_POOL_HANDLE;
	/* Sanity check */
	if ((*infolenptr > TLSPOOL_INFOBUFLEN) && (*infolenptr != 0xffff)) {
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
	/* Construct the command message */
	memset (&cmd, 0, sizeof (cmd));	/* Do not leak old stack info */
	cmd.pio_reqid = entry_reqid;
	cmd.pio_cbid = 0;
	cmd.pio_cmd = PIOC_INFO_V2;
	cmd.pio_data.pioc_info.info_kind = info_kind;
	cmd.pio_data.pioc_info.len = *infolenptr;
	memcpy (cmd.pio_data.pioc_info.ctlkey, ctlkey, TLSPOOL_CTLKEYLEN);
	if ((*infolenptr > 0) && (*infolenptr < TLSPOOL_INFOBUFLEN)) {
		memcpy (cmd.pio_data.pioc_info.buffer, infobuf, *infolenptr);
	}
	/* Send the command message */
	if (os_sendmsg_command (poolfd, &cmd, -1) == -1) {
		// Let SIGPIPE be reported as EPIPE
		registry_update (&entry_reqid, NULL);
		// errno inherited from sendmsg()
		return -1;
	}
	/* Await response and process it */
	registry_recvmsg (&regent);
	registry_update (&entry_reqid, NULL);
	switch (cmd.pio_cmd) {
	case PIOC_ERROR_V2:
		/* Bad luck, we failed */
		syslog (LOG_INFO, "TLS Pool error to tlspool_info(): %s", cmd.pio_data.pioc_error.message);
		errno = cmd.pio_data.pioc_error.tlserrno;
		return -1;
	case PIOC_INFO_V2:
		/* Wheee!!! we're done */
		*infolenptr = cmd.pio_data.pioc_info.len;
		if ((*infolenptr > 0) && (*infolenptr < TLSPOOL_INFOBUFLEN)) {
			memcpy (infobuf, cmd.pio_data.pioc_info.buffer, *infolenptr);
		}
		return 0;
	default:
		/* V2 protocol error */
		errno = EPROTO;
		return -1;
	}
}

