/* Asynchronous client API for the TLS Pool
 *
 * This is a minimalistic wrapper around the communication
 * with the TLS Pool.  Its functions are limited to passing
 * data structures from and to sockets, and giving acces
 * to event handler libraries.
 *
 * This interface intends to be portable.  It also aims
 * to be minimal, making it useful for two future directions:
 * networked TLS Pools and embedded/small TLS Pool support.
 *
 * From: Rick van Rein <rick@openfortress.nl>
 */


#include <stdbool.h>
#include <stdint.h>
#include <assert.h>

#include <errno.h>
#include <unistd.h>
#include <fcntl.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <tlspool/async.h>


#ifdef WINDOWS_PORT
/* Our main purpose with the asynchronous API is simplicity.
 * You can say a lot about the Windows platform, but not
 * that it is simple.  We may not be able to support it.
 *
 * Instead, what we could do is simulate the API on top of
 * the synchronous default API for Windows.  If we do this,
 * we should do it in such a manner that tools like libev
 * continue to work.
 */
#error "The asynchronous API is not available on Windows"
#endif


/* Initialise a new asynchronous TLS Pool handle.
 * This opens a socket, but it does not start the
 * suggested "ping" operation.  All fields in the
 * structure are initialised, so it may enter with
 * no information set at all.  You can request to
 * perform a blocking initial ping operation.
 *
 * Return true on success, false with errno on failure.
 */
bool tlspool_async_open (struct tlspool_async_handle *pool,
			size_t sizeof_tlspool_command,
			char *path,
			bool blocking_ping) {
	int sox = -1;
	//
	// Validate expectations of the caller
	if (sizeof (struct tlspool_command) != sizeof_tlspool_command) {
		errno = EPROTO;
		return false;
	}
	//
	// Initialise the structure with basic data
	memset (pool, 0, sizeof (pool));
	pool->cmdsize = sizeof_tlspool_command;
	//
	// Open the handle to the TLS Pool
#ifndef WINDOWS_PORT
	struct sockaddr_un sun;
	memset (&sun, 0, sizeof (sun));
	strcpy (sun.sun_path, (char *) path);
	sun.sun_family = AF_UNIX;
	sox = socket (AF_UNIX, SOCK_STREAM, 0);
	if (sox == -1) {
		goto fail_handle;
	}
	if (connect (sox, (struct sockaddr *) &sun, SUN_LEN (&sun)) != 0) {
		goto fail_handle_close;
	}
#else
	sox = open_named_pipe ((LPCTSTR) path);
	if (sox == INVALID_POOL_HANDLE) {
		//TODO// errno = ... (if not set yet)
		return false;
	}
#endif
	//
	// If requested, perform a synchronous ping.
	// This code is needed once in any program,
	// and blocking is easier.  Also, blocking
	// is not as offensive during initialisation
	// as later on, and this is quite simple.
	if (blocking_ping) {
		struct tlspool_command cmd;
		memset (&cmd, 0, sizeof (cmd));	/* Do not leak old stack info */
		cmd.pio_reqid = 1;
		cmd.pio_cbid = 0;
		cmd.pio_cmd = PIOC_PING_V2;
		if (send (sox, &cmd, sizeof (cmd), MSG_NOSIGNAL) != sizeof (cmd)) {
			errno = EPROTO;
			goto fail_handle_close;
		}
		if (recv (sox, &cmd, sizeof (cmd), MSG_NOSIGNAL) != sizeof (cmd)) {
			errno = EPROTO;
			goto fail_handle_close;
		}
		memcpy (&pool->pingdata, &cmd.pio_data.pioc_ping, sizeof (struct pioc_ping));
	}
	//
	// Make the connection non-blocking
	int soxflags = fcntl (sox, F_GETFL, 0);
	if (fcntl (sox, F_SETFL, soxflags | O_NONBLOCK) != 0) {
		goto fail_handle_close;
	}
	//
	// Report success
	pool->handle = sox;
	return true;
	//
	// Report failure
#ifndef WINDOWS_PORT
fail_handle_close:
	close (sox);
fail_handle:
	pool->handle = -1;
	return false;
#endif
}


/* Send a request to the TLS Pool and register a
 * callback handle for it.
 *
 * Return true on succes, false with errno on failure.
 */
bool tlspool_async_request (struct tlspool_async_handle *pool,
			struct tlspool_async_callback *reqcb,
			int opt_fd) {
	//
	// Consistency is better checked now than later
	assert (reqcb->cbfunc != NULL);
	//
	// Loop until we have a unique reqid
	bool not_done = true;
	while (not_done) {
		uint16_t reqid = (uint16_t) (random() & 0x0000ffff);
		reqcb->cmd.pio_reqid = reqid;
		struct tlspool_async_callback *prior_entry = NULL;
		HASH_FIND (hh, pool->requests, &reqcb->cmd.pio_reqid, 2, prior_entry);
		not_done = (prior_entry != NULL);
	}
	//
	// Insert into the hash table with the unique reqid
	HASH_ADD (hh, pool->requests, cmd.pio_reqid, 2, reqcb);
	//
	// Construct the message to send -- including opt_fd, if any
	struct iovec iov;
	struct cmsghdr *cmsg;
	struct msghdr mh;
	char anc [CMSG_SPACE(sizeof(int))];
	memset (&mh, 0, sizeof (mh));   /* do not leak stack contents */
	memset (&iov, 0, sizeof (iov));
	iov.iov_base = &reqcb->cmd;
	iov.iov_len = sizeof (struct tlspool_command);
	mh.msg_iov = &iov;
	mh.msg_iovlen = 1;
	if (opt_fd >= 0) {
		mh.msg_control = anc;
		mh.msg_controllen = sizeof (anc);
		cmsg = CMSG_FIRSTHDR (&mh);
		cmsg->cmsg_level = SOL_SOCKET;
		cmsg->cmsg_type = SCM_RIGHTS;
		*(int *)CMSG_DATA(cmsg) = opt_fd;	/* cannot close it yet */
		cmsg->cmsg_len = CMSG_LEN(sizeof(int));
	}
	//
	// Send the request to the TLS Pool
#ifdef WINDOWS_PORT
	ssize_t sent = np_send_command (&cmd);
#else
	ssize_t sent = sendmsg (pool->handle, &mh, MSG_NOSIGNAL);
#endif
	if (sent < sizeof (struct tlspool_command)) {
		/* Sending failed; drill down to see why */
		if (sent == 0) {
			/* This is not a problem, we can try again later */
			errno = EAGAIN;
			goto fail;
		} else if (sent < 0) {
			/* We got an errno value to return; socket is ok */
			goto fail;
		}
		/* Sending to the socket is no longer reliable */
		shutdown (pool->handle, SHUT_WR);
		errno = EPROTO;
		goto fail;
	}
	//
	// Return successfully
	return true;
	//
	// Return failure -- and always close the opt_fd, if any
fail:
	if (opt_fd >= 0) {
		close (opt_fd);
	}
	return false;
}


/* Cancel a request.  Do not trigger the callback.
 *
 * BE CAREFUL.  The TLS Pool can still send back a
 * response with the request identity, and you have
 * no way of discovering that if it arrives at a new
 * request.  EMBRACE FOR IMPACT.
 *
 * Return true on success, false with errno otherwise.
 */
bool tlspool_async_cancel (struct tlspool_async_handle *pool,
			struct tlspool_async_callback *reqcb) {
	//
	// Just rip the request from the hash, ignoring
	// what it will do when a response comes back
	HASH_DEL (pool->requests, reqcb);
	//
	// No sanity checks; you are not sane using this...
	return true;
}


/* Process all (but possibly no) outstanding requests
 * by reading any available data from the TLS Pool.
 *
 * Return true on success, false with errno otherwise.
 *
 * Specifically, when errno is EAGAIN or EWOULDBLOCK,
 * the return value is true to indicate business as
 * usual.
 */
bool tlspool_async_process (struct tlspool_async_handle *pool) {
	//
	// Reception structures
	// Note that we do not receive file descriptors
	// (maybe later -- hence opt_fd in the callback)
	struct tlspool_command cmd;
	struct iovec iov;
	struct cmsghdr *cmsg;
	struct msghdr mh;
	//NOT-USED// char anc [CMSG_SPACE(sizeof(int))];
	//
	// Start a loop reading from the TLS Pool
	while (true) {
		//
		// Prepare memory structures for reception
		memset (&cmd, 0, sizeof (cmd));   /* never, ever leak stack data */
		iov.iov_base = &cmd;
		iov.iov_len = sizeof (cmd);
		mh.msg_iov = &iov;
		mh.msg_iovlen = 1;
		//NOT-USED// mh.msg_control = anc;
		//NOT-USED// mh.msg_controllen = sizeof (anc);
		//
		// Receive the message and weigh the results
		ssize_t recvd = recvmsg (pool->handle, &mh, MSG_NOSIGNAL);
		if (recvd < sizeof (struct tlspool_command)) {
			/* Reception failed; drill down to see why */
			if (recvd == 0) {
				/* This is not a problem, we can try again */
				return true;
			} else if (recvd < 0) {
				/* We got an errno to pass; socket is ok */
				if ((errno == EAGAIN) || (errno == EWOULDBLOCK)) {
					errno = 0;
					return true;
				} else {
					return false;
				}
			}
			/* Receiving from the socket is no longer reliable */
			close (pool->handle);
			pool->handle = -1;
			errno = EPROTO;
			return false;
		}
		//
		// Find the callback routine
		struct tlspool_async_callback *reqcb = NULL;
		HASH_FIND (hh, pool->requests, &reqcb->cmd.pio_reqid, 2, reqcb);
		if (reqcb == NULL) {
			/* We do not have a callback, user should decide */
			errno = ENOENT;
			return false;
		}
		//
		// Take the callback function out of the hash
		HASH_DEL (pool->requests, reqcb);
		//
		// Invoke the callback; currently, we never receive an opt_fd
		reqcb->cbfunc (reqcb, -1);
		//
		// Continue processing with the next entry
	}
}


/* Indicate that a connection to the TLS Pool has been
 * closed down.  Cancel any pending requests by locally
 * generating error responses.
 *
 * Return true on success, false with errno otherwise.
 */
bool tlspool_async_closed (struct tlspool_async_handle *pool) {
	//
	// Locally clone the hash of pending requests
	struct tlspool_async_callback *stopit = pool->requests;
	pool->requests = NULL;
	//
	// Iterate over hash elements and callback on them
	struct tlspool_async_callback *here, *_tmp;
	HASH_ITER (hh, stopit, here, _tmp) {
		//
		// Remove the entry from the cloned hash
		HASH_DEL (stopit, here);
		//
		// Fill the cmd buffer with an error message
		here->cmd.pio_cmd = PIOC_ERROR_V2;
		here->cmd.pio_data.pioc_error.tlserrno = EPIPE;
		strncpy (here->cmd.pio_data.pioc_error.message,
			"Disconnected from the TLS Pool",
			sizeof (here->cmd.pio_data.pioc_error.message));
		//
		// Invoke the callback to process the error
		here->cbfunc (here, -1);
	}
	//
	// Return success.
	return true;
}


//TODO// How to register with an event loop?  The pool_handle_t is strange on Windows...

