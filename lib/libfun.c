/* tlspool/libfun.c -- Library function for starttls go-get-it */


#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <syslog.h>
#include <assert.h>

#include <unistd.h>
#include <pthread.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/select.h>
#include <sys/resource.h>

#include <tlspool/starttls.h>
#include <tlspool/commands.h>



/* The master thread will run the receiving side of the socket that connects
 * to the TLS Pool.  The have_master_lock is used with _trylock() and will
 * succeed to lock once, thereby approving the creation of the master thread.
 */

static pthread_mutex_t have_master_lock = PTHREAD_MUTEX_INITIALIZER;

static void *master_thread (void *path);

static int poolfd = -1;		/* Blocked retrieval with tlspool_socket() */

static pthread_cond_t updated_poolfd = PTHREAD_COND_INITIALIZER;

static pthread_mutex_t prng_lock = PTHREAD_MUTEX_INITIALIZER;


/* The library function for starttls, which is normally called through one
 * of the two inline variations below, which start client and server sides.
 *
 * As a side effect, this routine ensures that a master thread is running
 * on the poolfd.  This is the process that actually contacts the TLS Pool
 * and sets up the poolfd socket.
 */
int tlspool_socket (char *path) {
	int poolfdsample = poolfd;
	if (poolfdsample < 0) {
		pthread_mutex_t local_cond_wait = PTHREAD_MUTEX_INITIALIZER;
		//
		// Now that we have established a (first) poolfd, start up
		// the master thread that will recv() from it, and distribute.
		if (pthread_mutex_trylock (&have_master_lock) == 0) {
			pthread_t thr;
			unsigned int seed;
			pid_t me;
			if (!path) {
				path = TLSPOOL_DEFAULT_SOCKET_PATH;
			}
			if (strlen (path) + 1 > sizeof (((struct sockaddr_un *) NULL)->sun_path)) {
				syslog (LOG_ERR, "TLS Pool path name too long for UNIX domain socket");
				exit (1);
			}
			if (pthread_create (&thr, NULL, master_thread, (void *) path) != 0) {
				syslog (LOG_NOTICE, "Failed to create TLS Pool client master thread");
				pthread_mutex_unlock (&have_master_lock);
				close (poolfd);
				poolfd = -1;
				return -1;
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
		while (poolfdsample = poolfd, poolfdsample < 0) {
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
int tlspool_simultaneous_starttls (void) {
	static int simu = -1;
	if (simu < 0) {
		struct rlimit rlimit_nofile;
		if (getrlimit (RLIMIT_NOFILE, &rlimit_nofile) == -1) {
			syslog (LOG_NOTICE, "Failed to determine simultaneous STARTTLS: %s", strerror (errno));
			rlimit_nofile.rlim_max = 1024;  // Pick something
		}
		simu = rlimit_nofile.rlim_max / 2;  // 2 FDs per STARTTLS
	}
}


/* The request registry is an array of pointers, filled by the starttls_xxx()
 * functions for as long as they have requests standing out.  The registry
 * permits instant lookup of a mutex to signal, so the receiving end may
 * pickup the message in its also-registered tlspool command buffer.
 */

struct registry_entry {
	pthread_mutex_t *sig;		/* Wait for master thread's recvmsg() */
	struct tlspool_command *buf;	/* Buffer to hold received command */
	int pfd;			/* Client thread's assumed poolfd */
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
void registry_flush (int poolfd) {
	int regid = tlspool_simultaneous_starttls ();
	assert (pthread_mutex_lock (&registry_lock) == 0);
	while (regid-- > 0) {
		struct registry_entry *entry = registry [regid];
		if ((entry != NULL) && (entry->pfd != poolfd)) {
			// Fill the cmd buffer with an error message
			entry->buf->pio_cmd = PIOC_ERROR_V1;
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
	useconds_t usec;
	struct sockaddr_un sun;
	struct tlspool_command cmd;
	//NOT-USED// char anc [CMSG_SPACE(sizeof (int))];
	struct iovec iov;
	struct cmsghdr *cmsg;
	struct msghdr mh = { 0 };
	struct registry_entry *entry;

	//
	// Setup path information -- value and size were checked
	bzero (&sun, sizeof (sun));
	strcpy (sun.sun_path, (char *) path);
	sun.sun_family = AF_UNIX;
	//
	// Service forever
	while (1) {
		//
		// If any old socket clients persist, tell them that the
		// TLS Pool has been disconnected.
		if (poolfd >= 0) {
			int poolfdcopy = poolfd;
printf ("DEBUG: Removing old poolfd %d\n", poolfd);
			poolfd = -1;
			registry_flush (-1);
			close (poolfdcopy);
		}
		//
		// First, connect to the TLS Pool; upon failure, retry
		// with 1s, 2s, 4s, 8s, 16s, 32s, 32s, 32s, ... intervals.
		usec = 1000000;
		while (poolfd < 0) {
			int newpoolfd = socket (AF_UNIX, SOCK_STREAM, 0);
			if (newpoolfd != -1) {
				if (connect (newpoolfd, (struct sockaddr *) &sun, SUN_LEN (&sun)) == 0) {
printf ("DEBUG: Succeeded connect() to TLS Pool\n");
					poolfd = newpoolfd;
				} else {
					close (newpoolfd);
					newpoolfd = -1;
				}
			}
printf ("DEBUG: Trying new poolfd %d for path %s\n", poolfd, sun.sun_path);
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
printf ("DEBUG: Signalled slave threads with poolfd %d\n", poolfd);
			//
			// Wait before repeating, with exponential back-off
			if (poolfd < 0) {
				usleep (usec);
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
			iov.iov_base = &cmd;
			iov.iov_len = sizeof (cmd);
			mh.msg_iov = &iov;
			mh.msg_iovlen = 1;
			//NOT-USED// mh.msg_control = anc;
			//NOT-USED// mh.msg_controllen = sizeof (anc);
			retval = recvmsg (poolfd, &mh, MSG_NOSIGNAL);
			if (retval == 0) {
				errno = EPIPE;
				retval = -1;
			}
			if (retval == -1) {
				// This includes EPIPE, or EOF, for detached
				// TLS Pool; the treatment is to reconnect.
printf ("DEBUG: recvmsg() returned -1 due to: %s\n", strerror (errno));
				break;
			}
			//
			// Determine where to post the received message
			entry = registry [cmd.pio_reqid];
			if (entry == NULL) {
				// Protocol error!  Client detached!
printf ("DEBUG: Client detached! poolfd=%d, cmd=0x%08x, reqid=%d, cbid=%d\n", poolfd, cmd.pio_cmd, cmd.pio_reqid, cmd.pio_cbid);
				if ((cmd.pio_cbid != 0) && (cmd.pio_cmd != PIOC_ERROR_V1)) {
printf ("DEBUG: Will send PIOC_ERROR_V1 as callback to TLS Pool\n");
					// TLS Pool is waiting for a callback;
					// Send it an ERROR message instead.
					cmd.pio_cmd = PIOC_ERROR_V1;
					cmd.pio_data.pioc_error.tlserrno = EPIPE;
					strncpy (cmd.pio_data.pioc_error.message, "Client prematurely left TLS Pool negotiations", sizeof (cmd.pio_data.pioc_error.message));
					sendmsg (poolfd, &mh, MSG_NOSIGNAL);
					// Ignore errors
printf ("DEBUG: Sent      PIOC_ERROR_V1 as callback to TLS Pool\n");
				}
				// Do not attempt delivery
				continue;
			}
			if (entry->pfd != poolfd) {
printf ("DEBUG: Registry entry has older poolfd %d not %d, flushing registry\n", entry->pfd, poolfd);
				registry_flush (poolfd);
			}
			memcpy (entry->buf, &cmd, sizeof (cmd));
			//NOT-USED// deliver anc or passfd to recipient
			pthread_mutex_unlock (entry->sig);
printf ("DEBUG: Signalled slave with new message in place\n");
		}
	}
}


/* Consider handling the message reception interface, if no other thread is
 * doing that yet.  Then, wait until a message has been received.
 */
void registry_recvmsg (struct registry_entry *entry) {
	static int lastpoolfd = -1;
	//
	// Detect poolfd socket change for potential dangling recipients
	if (entry->pfd != lastpoolfd) {
		lastpoolfd = tlspool_socket (NULL);
		if ((entry->pfd != lastpoolfd) && (lastpoolfd != -1)) {
			// Signal PIOC_ERROR to outdated recipients.
			// (That will include the current recipient.)
			registry_flush (lastpoolfd);
		}
	}
	//
	// Now wait for the registered command structure to be filled
	// by the master thread.  Note that the call to tlspool_socket()
	// above is made when this function is first called, and that
	// routine ensures running of the master thread.
	assert (pthread_mutex_lock (entry->sig) == 0);
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
int _tlspool_starttls (int server, int cryptfd, starttls_t *tlsdata,
			void *privdata,
			int namedconnect (starttls_t *tlsdata,void *privdata)) {
	struct tlspool_command cmd;
	pthread_mutex_t recvwait = PTHREAD_MUTEX_INITIALIZER;
	struct registry_entry regent = { .sig = &recvwait, .buf = &cmd };
	int entry_reqid = -1;
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
		errno = ENODEV;
		return -1;
	}
	/* Finish setting up the registry entry */
	regent.pfd = poolfd;
	pthread_mutex_lock (&recvwait);		// Will await unlock by master
	/* Determine the request ID */
	if (registry_update (&entry_reqid, &regent) != 0) {
		close (cryptfd);
		errno = EBUSY;
		return -1;
	}
	bzero (&cmd, sizeof (cmd));	/* Do not leak old stack info */
	cmd.pio_reqid = entry_reqid;
	cmd.pio_cbid = 0;
	cmd.pio_cmd = server? PIOC_STARTTLS_SERVER_V2: PIOC_STARTTLS_CLIENT_V2;
	memcpy (&cmd.pio_data.pioc_starttls, tlsdata, sizeof (struct pioc_starttls));

#if RAND_MAX < 0xfffff
#  error "Failure on assumption of 16 bits of random material per random() call"
#endif

#if TLSPOOL_CTLKEYLEN != 16
#  error "Failure on assumption of 16 bytes per ctlkey"
#endif

	assert (pthread_mutex_lock (&prng_lock) == 0);
	* (uint16_t *) &cmd.pio_data.pioc_starttls.ctlkey [ 0] = random ();
	* (uint16_t *) &cmd.pio_data.pioc_starttls.ctlkey [ 2] = random ();
	* (uint16_t *) &cmd.pio_data.pioc_starttls.ctlkey [ 4] = random ();
	* (uint16_t *) &cmd.pio_data.pioc_starttls.ctlkey [ 6] = random ();
	* (uint16_t *) &cmd.pio_data.pioc_starttls.ctlkey [ 8] = random ();
	* (uint16_t *) &cmd.pio_data.pioc_starttls.ctlkey [10] = random ();
	* (uint16_t *) &cmd.pio_data.pioc_starttls.ctlkey [12] = random ();
	* (uint16_t *) &cmd.pio_data.pioc_starttls.ctlkey [14] = random ();
	pthread_mutex_unlock (&prng_lock);
printf ("DEBUG: ctlkey =");
{int i; for (i=0;i<16;i++) printf (" %02x", cmd.pio_data.pioc_starttls.ctlkey [i]);}
printf ("\n");

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
	if (sendmsg (poolfd, &mh, MSG_NOSIGNAL) == -1) {
		// Let SIGPIPE be reported as EPIPE
		close (cryptfd);
		registry_update (&entry_reqid, NULL);
		// errno inherited from sendmsg()
		return -1;
	}
	sentfd = cryptfd;  /* Close anytime after response and before fn end */

	/* Handle responses until success or error */
	processing = 1;
	while (processing) {
		//NOTUSED// mh.msg_control = anc;
		//NOTUSED// mh.msg_controllen = sizeof (anc);
		registry_recvmsg (&regent);
		switch (cmd.pio_cmd) {
		case PIOC_ERROR_V1:
			/* Bad luck, we failed */
			syslog (LOG_INFO, "TLS Pool error to _starttls_libfun(): %s", cmd.pio_data.pioc_error.message);
			close (sentfd);
			registry_update (&entry_reqid, NULL);
			errno = cmd.pio_data.pioc_error.tlserrno;
			return -1;
		case PIOC_PLAINTEXT_CONNECT_V2:
			if (namedconnect) {
				plainfd = namedconnect (tlsdata, privdata);
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
			if (sendmsg (poolfd, &mh, MSG_NOSIGNAL) == -1) {
				// Let SIGPIPE be reported as EPIPE
				close (sentfd);
				registry_update (&entry_reqid, NULL);
				// errno inherited from sendmsg()
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
			close (sentfd);
			registry_update (&entry_reqid, NULL);
			errno = EPROTO;
			return -1;
		}
	}

	/* Close the now-duplicated or now-erradicated plaintext fd */
	close (sentfd);

	memcpy (tlsdata, &cmd.pio_data.pioc_starttls, sizeof (struct pioc_starttls));
printf ("DEBUG: Returning control key %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\n", tlsdata->ctlkey [0], tlsdata->ctlkey [1], tlsdata->ctlkey [2], tlsdata->ctlkey [3], tlsdata->ctlkey [4], tlsdata->ctlkey [5], tlsdata->ctlkey [6], tlsdata->ctlkey [7], tlsdata->ctlkey [8], tlsdata->ctlkey [9], tlsdata->ctlkey [10], tlsdata->ctlkey [11], tlsdata->ctlkey [12], tlsdata->ctlkey [13], tlsdata->ctlkey [14], tlsdata->ctlkey [15]);
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
	poolfd = tlspool_socket (NULL);
	if (poolfd == -1) {
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
	bzero (&cmd, sizeof (cmd));	/* Do not leak old stack info */
	cmd.pio_reqid = entry_reqid;
	cmd.pio_cbid = 0;
	cmd.pio_cmd = cmdcode;
	memcpy (&cmd.pio_data.pioc_control.ctlkey, ctlkey, TLSPOOL_CTLKEYLEN);
printf ("DEBUG: Using control key %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\n", cmd.pio_data.pioc_control.ctlkey [0], cmd.pio_data.pioc_control.ctlkey [1], cmd.pio_data.pioc_control.ctlkey [2], cmd.pio_data.pioc_control.ctlkey [3], cmd.pio_data.pioc_control.ctlkey [4], cmd.pio_data.pioc_control.ctlkey [5], cmd.pio_data.pioc_control.ctlkey [6], cmd.pio_data.pioc_control.ctlkey [7], cmd.pio_data.pioc_control.ctlkey [8], cmd.pio_data.pioc_control.ctlkey [9], cmd.pio_data.pioc_control.ctlkey [10], cmd.pio_data.pioc_control.ctlkey [11], cmd.pio_data.pioc_control.ctlkey [12], cmd.pio_data.pioc_control.ctlkey [13], cmd.pio_data.pioc_control.ctlkey [14], cmd.pio_data.pioc_control.ctlkey [15]);

	/* Send the request */
	if (send (poolfd, &cmd, sizeof (cmd), MSG_NOSIGNAL) == -1) {
		// Let SIGPIPE be reported as EPIPE
		registry_update (&entry_reqid, NULL);
		// errno inherited from send()
		return -1;
	}

	/* Receive the response */
	registry_recvmsg (&regent);
	switch (cmd.pio_cmd) {
	case PIOC_SUCCESS_V1:
		retval = 0;
		break;
	case PIOC_ERROR_V1:
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

