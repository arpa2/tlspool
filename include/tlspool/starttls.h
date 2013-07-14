/* tlspool/starttls.h -- Library functions to invoke from clients/servers */

#ifndef TLSPOOL_STARTTLS_H
#define TLSPOOL_STARTTLS_H


#include <tlspool/commands.h>


/*
 * These functions are used by application software to turn an existing
 * connection into one that runs over TLS or DTLS.  These functions are
 * not just used after an acknowledged STARTTLS exchange, but can also
 * be used immediately on a newly opened connection running an xxxs:
 * secure variation of a standard protocol xxx:  -- usually, the two
 * versions each have their own default port.
 *
 * The starttls_ operations can consume a fair amount of time to finish,
 * so future versions may provide asynchronous variations.  At present,
 * the calls are not re-entrant.  TODO: asynchronicity & request pooling.
 */


#define TLSPOOL_DEFAULT_SOCKET_PATH "/var/run/tlspool.sock"


/* Setup the TLS pool socket to use, if it is not the default path name
 * /var/run/tlspool.sock.  The return value is the file descriptor for the
 * pool.  This function can be called again, in which case the argument is
 * ignored and the previously set socket is returned.  The function can also
 * be called with NULL in the first call, in which case the default location
 * is used.
 */
int tlspool_socket (char *path);


/* The library function for starttls, which is normally called through one
 * of the two inline variations below, which start client and server sides.
 */
int _starttls_libfun (int server, int fd, starttls_t *tlsdata, int checksni (char *,size_t));


/* The starttls_client() call is an inline wrapper around the library
 * function that combines client and server operations.
 *
 * The tlsdata structure will be copied into the command structure,
 * and upon completion it will be copied back.  You can use it to
 * communicate flags, protocols and other parameters, including the
 * most important settings -- local and remote identifiers.  See
 * the socket protocol document for details.
 *
 * The function returns -1 on error, and sets errno appropriately.
 */
static inline int starttls_client (int fd, starttls_t *tlsdata) {
	return _starttls_libfun (0, fd, tlsdata, NULL);
}


/* The starttls_server() call is an inline warpper around the library
 * function that combiners client and server operations.
 *
 * The tlsdata structure will be copied into the command structure,
 * and upon completion it will be copied back.  You can use it to
 * communicate flags, protocols and other parameters, including the
 * most important settings -- local and remote identifiers.  See
 * the socket protocol document for details.
 *
 * The checksni() function is a callback that is used to verify if a
 * proposed local identifier is acceptable.  The buffer along with its
 * size including trailing NUL character is provided, and may be
 * reviewed.  Note that the actual string stored in the buffer may be
 * shorter; the room is provided to offer place for alternate proposals
 * of local identities.  The function may disagree with a name without
 * proposing an alternative by setting the buffer to an emptry string or
 * by returning zero.  Non-zero returned from checksni() means to use
 * the buffer value as it is upon return.
 *
 * The function returns -1 on error, and sets errno appropriately.
 */
static inline int starttls_server (int fd, starttls_t *tlsdata, int checksni (char *,size_t)) {
	return _starttls_libfun (1, fd, tlsdata, checksni);
}



#endif // TLSPOOL_STARTTLS_H
