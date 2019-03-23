/* tlspool/async.h -- Asynchronous API functions and data structures */


#include <stdbool.h>
#include <stdint.h>

#include <tlspool/uthash.h>
#include <tlspool/commands.h>


/* OS independent pool handle
 */
#ifdef WINDOWS_PORT
typedef struct {
	OVERLAPPED oOverlap;
	HANDLE hPipeInst;
	struct tlspool_command chRequest;
	DWORD cbRead;
	DWORD dwState;
	BOOL fPendingIO;
} PIPEINST, *LPPIPEINST;
typedef LPPIPEINST pool_handle_t;
#define INVALID_POOL_HANDLE NULL
#else /* WINDOWS_PORT */
typedef int pool_handle_t;
#define INVALID_POOL_HANDLE -1
#endif /* WINDOWS_PORT */ 


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
	void (*cbfunc) (struct tlspool_async_callback *cbdata);
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
	char YYYYMMDD_producer [8+128];
	uint32_t facilities;
};


/* Initialise a new asynchronous TLS Pool handle.
 * This opens a socket, but it does not start the
 * suggested "ping" operation.  All fields in the
 * structure are initialised, so it may enter with
 * no information set at all.
 *
 * Return true on success, false with errno on failure.
 */
bool tlspool_async_open (struct tlspool_async_handle *pool,
			size_t sizeof_tlspool_command);


/* Send a request to the TLS Pool and register a
 * callback handle for it.
 *
 * Return true on succes, false with errno on failure.
 */
bool tlspool_async_request (struct tlspool_async_handle *pool,
			struct tlspool_async_callback *reqcb);


/* Cancel a request.
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
 */
bool tlspool_async_process (struct tlspool_async_handle *pool);


/* Indicate that a connection to the TLS Pool has been
 * closed down.  Cancel any pending requests by locally
 * generating error responses.
 */
bool tlspool_async_closed (struct tlspool_async_handle *pool);


//TODO// How to register with an event loop?  The pool_handle_t is strange on Windows...

