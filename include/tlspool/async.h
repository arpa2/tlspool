/* tlspool/async.h -- Asynchronous API functions and data structures */


#include <stdbool.h>
#include <stdint.h>

#include <tlspool/uthash.h>
#include <tlspool/commands.h>


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


/* POSIX pool handle type.
 */
typedef int pool_handle_t;


/* The tlspool_async_callback structure manages
 * a single pending request.  Once a response arrives,
 * the structure is taken out of the hash table and
 * the `cbfunc()` is invoked with the structure as
 * its parameter.
 *
 * This structure is allocated by the caller, and
 * borrowed as part of the hash pool while its request
 * is pending.  Once replied, it can be recycled.
 *
 * Requests in the hash table are identified by the
 * request identity.
 */
struct tlspool_async_callback {
	UT_hash_handle hh;
	void (*cbfunc) (struct tlspool_async_callback *cbdata, int opt_fd);
	struct tlspool_command cmd;
};


/* The tlspool_async_socket manages the socket that
 * connects to the TLS Pool.  It is the starting
 * point for the hash table of pending requests.
 *
 * You should initiatlise the structure with the
 * cmdsize set to sizeof (struct tlspool_command)
 * and all modules can assert() if it is proper.
 * The remaining fields start zeroed, but you are
 * suggested to "ping" the TLS Pool and set the
 * fields "YYYYMMDD_producer" and "facilities"
 * with its output.
 */
struct tlspool_async_handle {
	pool_handle_t handle;
	size_t cmdsize;
	struct tlspool_async_callback *requests;
	struct pioc_ping pingdata;
};


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
			bool blocking_ping);


/* Send a request to the TLS Pool and register a
 * callback handle for it.
 *
 * Return true on succes, false with errno on failure.
 */
bool tlspool_async_request (struct tlspool_async_handle *pool,
			struct tlspool_async_callback *reqcb,
			int opt_fd);


/* Cancel a request.  Do not trigger the callback.
 *
 * BE CAREFUL.  The TLS Pool can still send back a
 * response with the request identity, and you have
 * no way of discovering that if it arrives at a new
 * request.
 *
 * Return true on success, false with errno otherwise.
 */
bool tlspool_async_cancel (struct tlspool_async_handle *pool,
			struct tlspool_async_callback *reqcb);


/* Process all (but possibly no) outstanding requests
 * by reading any available data from the TLS Pool.
 *
 * Return true on success, false with errno otherwise.
 *
 * Specifically, when errno is EAGAIN or EWOULDBLOCK,
 * the return value is true to indicate business as
 * usual.
 */
bool tlspool_async_process (struct tlspool_async_handle *pool);


/* Indicate that a connection to the TLS Pool has been
 * closed down.  Cancel any pending requests by locally
 * generating error responses.
 *
 * Return true on success, false with errno otherwise.
 */
bool tlspool_async_closed (struct tlspool_async_handle *pool);


//TODO// How to register with an event loop?  The pool_handle_t is strange on Windows...

