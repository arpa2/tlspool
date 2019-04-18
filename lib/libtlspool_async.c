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


#include <stdlib.h>
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
#include <tlspool/starttls.h>


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
 * This opens a socket, embedded into the pool
 * structure.
 *
 * It is common, and therefore supported in this
 * call, to start with a "ping" operation to
 * exchange version information and supported
 * facilities.  Since this is going to be in all
 * code, where it would be difficult due to the
 * asynchronous nature of the socket, we do it
 * here, just before switching to asynchronous
 * mode.  It is usually not offensive to bootstrap
 * synchronously, but for some programs it may
 * incur a need to use a thread pool to permit
 * the blocking wait, or (later) reconnects can
 * simply leave the identity to provide NULL and
 * not TLSPOOL_IDENTITY_V2 which you would use to
 * allow this optional facility.  We will ask
 * for PIOF_FACILITY_ALL_CURRENT but you want to
 * enforce less, perhaps PIOF_FACILITY_STARTTLS,
 * as requesting too much would lead to failure
 * opening the connection to the TLS Pool.
 *
 * Return true on success, false with errno on failure.
 */
bool tlspool_async_open (struct tlspool_async_pool *pool,
			size_t sizeof_tlspool_command,
			char *tlspool_identity,
			uint32_t required_facilities,
			char *socket_path) {
	int sox = -1;
	//
	// Validate expectations of the caller
	if (sizeof (struct tlspool_command) != sizeof_tlspool_command) {
		errno = EPROTO;
		return false;
	}
	//
	// Find the socket_path to connect to
	if (socket_path == NULL) {
		socket_path = tlspool_configvar (NULL, "socket_name");
	}
	if (socket_path == NULL) {
		socket_path = TLSPOOL_DEFAULT_SOCKET_PATH;
	}
	//
	// Initialise the structure with basic data
	memset (pool, 0, sizeof (*pool));
	pool->cmdsize = sizeof_tlspool_command;
	//
	// Open the handle to the TLS Pool
#ifndef WINDOWS_PORT
	struct sockaddr_un sun;
	memset (&sun, 0, sizeof (sun));
	strcpy (sun.sun_path, socket_path);
	sun.sun_family = AF_UNIX;
	sox = socket (AF_UNIX, SOCK_STREAM, 0);
	if (sox == -1) {
		goto fail_handle;
	}
	if (connect (sox, (struct sockaddr *) &sun, SUN_LEN (&sun)) != 0) {
		goto fail_handle_close;
	}
#else
	sox = open_named_pipe ((LPCTSTR) socket_path);
	if (sox < 0) {
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
	if (required_facilities != 0) {
		struct tlspool_command poolcmd;
		memset (&poolcmd, 0, sizeof (poolcmd));	/* Do not leak old stack info */
		poolcmd.pio_reqid = 1;
		poolcmd.pio_cbid = 0;
		poolcmd.pio_cmd = PIOC_PING_V2;
		//
		// Tell the TLS Pool what we think of them, and what we would like to have
		assert (strlen (tlspool_identity) < sizeof (poolcmd.pio_data.pioc_ping.YYYYMMDD_producer));
		strcpy (poolcmd.pio_data.pioc_ping.YYYYMMDD_producer, tlspool_identity);
		poolcmd.pio_data.pioc_ping.facilities = required_facilities | PIOF_FACILITY_ALL_CURRENT;
		//
		// Send the request and await its response -- no contenders makes life easy
		if (send (sox, &poolcmd, sizeof (poolcmd), MSG_NOSIGNAL) != sizeof (poolcmd)) {
			errno = EPROTO;
			goto fail_handle_close;
		}
		if (recv (sox, &poolcmd, sizeof (poolcmd), MSG_NOSIGNAL) != sizeof (poolcmd)) {
			errno = EPROTO;
			goto fail_handle_close;
		}
		//
		// In any case, return the negotiated data; then be sure it meets requirements
		memcpy (&pool->pingdata, &poolcmd.pio_data.pioc_ping, sizeof (struct pioc_ping));
		if ((pool->pingdata.facilities & required_facilities) != required_facilities) {
			errno = ENOSYS;
			goto fail_handle_close;
		}
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
bool tlspool_async_request (struct tlspool_async_pool *pool,
			struct tlspool_async_request *reqcb,
			int opt_fd) {
	//
	// Consistency is better checked now than later
	assert (reqcb->cbfunc != NULL);
	//
	// Loop until we have a unique reqid
	bool not_done = true;
	do {
		uint16_t reqid = (uint16_t) (random() & 0x0000ffff);
		reqcb->cmd.pio_reqid = reqid;
		struct tlspool_async_request *prior_entry = NULL;
		HASH_FIND (hh, pool->requests, &reqid, 2, prior_entry);
		//LIST_STYLE// DL_SEARCH_SCALAR (pool->requests, prior_entry, cmd.pio_reqid, reqid);
		not_done = (prior_entry != NULL);
	} while (not_done);
	//
	// Insert into the hash table with the unique reqid
	HASH_ADD (hh, pool->requests, cmd.pio_reqid, 2, reqcb);
	//LIST_STYLE// DL_APPEND (pool->requests, reqcb);
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
	ssize_t sent = np_send_command (&poolcmd);
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
bool tlspool_async_cancel (struct tlspool_async_pool *pool,
			struct tlspool_async_request *reqcb) {
	//
	// Just rip the request from the hash, ignoring
	// what it will do when a response comes back
	HASH_DEL (pool->requests, reqcb);
	//LIST_STYLE// DL_DELETE (pool->requests, reqcb);
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
bool tlspool_async_process (struct tlspool_async_pool *pool) {
	//
	// Start a loop reading from the TLS Pool
	while (true) {
		//
		// Reception structures
		// Note that we do not receive file descriptors
		// (maybe later -- hence opt_fd in the callback)
		struct tlspool_command poolcmd;
		struct iovec iov;
		struct cmsghdr *cmsg;
		struct msghdr mh = { 0 };
		//NOT-USED// char anc [CMSG_SPACE(sizeof(int))];
		//
		// Prepare memory structures for reception
		memset (&poolcmd, 0, sizeof (poolcmd));   /* never, ever leak stack data */
		iov.iov_base = &poolcmd;
		iov.iov_len = sizeof (poolcmd);
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
		struct tlspool_async_request *reqcb = NULL;
		HASH_FIND (hh, pool->requests, &poolcmd.pio_reqid, 2, reqcb);
		//LIST_STYLE// DL_SEARCH_SCALAR (pool->requests, reqcb, cmd.pio_reqid, poolcmd.pio_reqid);
		if (reqcb == NULL) {
			/* We do not have a callback, user should decide */
			errno = ENOENT;
			return false;
		}
		//
		// Take the callback function out of the hash
		HASH_DEL (pool->requests, reqcb);
		//LIST_STYLE// DL_DELETE (pool->requests, reqcb);
		//
		// Clone the command structure to the request structure
		memcpy (&reqcb->cmd, &poolcmd, sizeof (reqcb->cmd));
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
bool tlspool_async_close (struct tlspool_async_pool *pool,
				bool close_socket) {
	//
	// Should we try to close the underlying socket
	if (close_socket && (pool->handle >= 0)) {
		close (pool->handle);
	}
	//
	// Locally clone the hash of pending requests
	struct tlspool_async_request *stopit = pool->requests;
	pool->requests = NULL;
	//
	// Iterate over hash elements and callback on them
	struct tlspool_async_request *here, *_tmp;
	HASH_ITER (hh, stopit, here, _tmp)
	//LIST_STYLE// DL_FOREACH_SAFE (stopit, here, _tmp)
	{
		//
		// Remove the entry from the cloned hash
		HASH_DEL (stopit, here);
		//LIST_STYLE// DL_DELETE (stopit, here);
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


//TODO// How to register with an event loop?  The int is strange on Windows...

