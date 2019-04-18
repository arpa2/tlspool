/* tlspool/async.h -- Asynchronous API functions and data structures */


#include <stdbool.h>
#include <stdint.h>

#include <tlspool/uthash.h>
//LIST_STYLE// #include <tlspool/utlist.h>
#include <tlspool/starttls.h>

/* The tlspool_async_request structure manages
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
struct tlspool_async_request {
	UT_hash_handle hh;
	//LIST_STYLE// struct tlspool_async_request *next;
	//LIST_STYLE// struct tlspool_async_request *prev;
	void (*cbfunc) (struct tlspool_async_request *cbdata, int opt_fd);
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
struct tlspool_async_pool {
	int handle;
	size_t cmdsize;
	struct tlspool_async_request *requests;
	struct pioc_ping pingdata;
};


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
			char *socket_path);


/* Send a request to the TLS Pool and register a
 * callback handle for it.
 *
 * Return true on succes, false with errno on failure.
 */
bool tlspool_async_request (struct tlspool_async_pool *pool,
			struct tlspool_async_request *reqcb,
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
bool tlspool_async_cancel (struct tlspool_async_pool *pool,
			struct tlspool_async_request *reqcb);


/* Process all (but possibly no) outstanding requests
 * by reading any available data from the TLS Pool.
 *
 * Return true on success, false with errno otherwise.
 *
 * Specifically, when errno is EAGAIN or EWOULDBLOCK,
 * the return value is true to indicate business as
 * usual.
 */
bool tlspool_async_process (struct tlspool_async_pool *pool);


/* Indicate that a connection to the TLS Pool has been
 * closed down.  Cancel any pending requests by locally
 * generating error responses.
 *
 * Return true on success, false with errno otherwise.
 */
bool tlspool_async_close (struct tlspool_async_pool *pool,
				bool close_socket);


//TODO// How to register with an event loop?  The int is strange on Windows...

