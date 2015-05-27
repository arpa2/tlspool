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
			int namedconnect (starttls_t *tlsdata, void *privdata));


/* The library function to send a control connection command, notably
 * TLSPOOL_CONTROL_DETACH and TLSPOOL_CONTROL_REATTACH.
 *
 * This function returns zero on success, and -1 on failure.  In case of
 * failure, errno will be set.
 */
int _tlspool_control_command (int cmd, uint8_t *ctlkey);


/* Explicitly detach a TLS session from the controlling connection to the
 * TLS Pool.  This means that the control connection (and so, this program)
 * can be taken down without affecting the TLS session as it is setup.  It
 * also means that any control connection (including ones from other processes
 * and other programs) can reattach, using the ctlkey for the TLS session.
 *
 * The return value is 0 for success, -1 for failure.  In case of failure,
 * errno will also be set.
 */
static inline int tlspool_control_detach (uint8_t *ctlkey) {
	return _tlspool_control_command (PIOC_CONTROL_DETACH_V2, ctlkey);
}

/* Explicitly reattach a control connection to a TLS session.  This may be
 * called on a TLS session that is detached, by any process or program that
 * presents the proper control key.
 *
 * The return value is 0 for success, -1 for failure.  In case of failure,
 * errno will also be set.
 */
static inline int tlspool_control_reattach (uint8_t *ctlkey) {
	return _tlspool_control_command (PIOC_CONTROL_REATTACH_V2, ctlkey);
}


/* Register a callback function for local identity selection with the
 * LIDENTRY API of the TLS Pool.  This will invoke the callback with zero
 * or more database entries (marked with flag PIOF_LIDENTRY_DBENTRY) and an
 * inquiry (without that flag) to enter a local identity.  The callback is
 * expected to save the database entries in some sort of a menu structure
 * (or ignore it if it is not interested in them) and use them in the
 * selection process.  What it does precisely is up to the registered
 * application.
 *
 * The callback behaviour of the API can be influenced in various ways;
 * see the PIOF_LIDENTRY_xxx flags in <tlspool/commands.h> for details.
 * Some flags are used during registration and supplied in regflags,
 * some are used during callback and exchanged in the tlspool_command.
 *
 * The registration for callback terminates in the following situations:
 *  - the TLS Pool file handle is closed
 *  - the callback returns a wrong type of command, including PIOC_ERROR_xx
 *  - the callback does not respond fast enough (other apps may overtake)
 *
 * The responsetimeout is set to the number of seconds that a callback
 * may at most take to respond.  The claim on the registration will expire
 * after this time has passed.
 *
 * Note that the service function does not return until the callback
 * registration is terminated.  This is why it is called xxx_service and
 * not xxx_callback.  You may want to use a thread if your intention is
 * to do other things as well.  Note however, that it is usually a good
 * idea to keep localid handling separate, as a GUI function, from the
 * other components that interact with the TLS Pool for other purposes,
 * such as wrapping an application protocol.
 *
 * This function returns 0 on success, meaning it has gotten to a stage
 * where it was registered with the TLS Pool.  Otherwise, it returns -1
 * and sets errno.
 */
typedef void (*lidentry_callback_t) (struct tlspool_command *tc, void *data);
int tlspool_localid_service (uint32_t regflags, int responsetimeout, lidentry_callback_t lidcb, void *data);



#endif // TLSPOOL_STARTTLS_H
