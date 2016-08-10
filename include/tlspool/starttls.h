/* tlspool/starttls.h -- Library functions to invoke from clients/servers */

#ifndef TLSPOOL_STARTTLS_H
#define TLSPOOL_STARTTLS_H

#ifdef __cplusplus
extern "C"
{
#endif

#include <tlspool/commands.h>

#ifdef WINDOWS_PORT
#include <windows.h>
#else
#include <unistd.h>
#endif /* WINDOWS_PORT */


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


#ifdef WINDOWS_PORT
#define TLSPOOL_DEFAULT_CONFIG_PATH "/etc/tlspool.conf.windows"
#define TLSPOOL_DEFAULT_SOCKET_PATH "\\\\.\\pipe\\tlspool"
#define TLSPOOL_DEFAULT_PIDFILE_PATH "/var/run/tlspool.pid"
#else
#define TLSPOOL_DEFAULT_CONFIG_PATH "/etc/tlspool.conf"
#define TLSPOOL_DEFAULT_SOCKET_PATH "/var/run/tlspool.sock"
#define TLSPOOL_DEFAULT_PIDFILE_PATH "/var/run/tlspool.pid"
#endif /* WINDOWS_PORT */

/* Retrieve the process identity of the TLS Pool from the named file, or fall
 * back on the default file if the name is set to NULL.  Returns -1 on failure.
 */
int tlspool_pid (char *opt_pidfile);

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

/* Setup the TLS pool socket to use, if it is not the default path name
 * /var/run/tlspool.sock.  The return value is the file descriptor for the
 * pool.  This function can be called again, in which case the argument is
 * ignored and the previously set socket is returned.  The function can also
 * be called with NULL in the first call, in which case the default location
 * is used.
 */
pool_handle_t tlspool_open_poolhandle (char *path);

/* Close a pool handle
 */
#ifdef WINDOWS_PORT
static inline void tlspool_close_poolhandle (pool_handle_t poolh) {
	CloseHandle (poolh);
}
#else /* WINDOWS_PORT */
static inline void tlspool_close_poolhandle (pool_handle_t poolh) {
	close (poolh);
}
#endif /* WINDOWS_PORT */


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
int tlspool_ping (pingpool_t *pingdata);


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
int tlspool_localid_service (char *path, uint32_t regflags, int responsetimeout, char * (*cb) (struct pioc_lidentry *entry, void *data), void *data);


/* The library function to service PIN entry callbacks.  It registers
 * with the TLS Pool and will service callback requests until it is no
 * longer welcomed.  Of course, if another process already has a claim on
 * this functionality, the service offering will not be welcome from the
 * start.
 *
 * This function differs from most other TLS Pool library functions in
 * setting up a private socket.  This helps to avoid the overhead in the
 * foreseeable applications that only do this; it also helps to close
 * down the exclusive claim on local identity resolution when (part of)
 * the program is torn down.  The function has been built to cleanup
 * properly when it is subjected to pthread_cancel().
 *
 * The path parameter offers a mechanism to specify the socket path.  When
 * set to NULL, the library's compiled-in default path will be used.
 *
 * In terms of linking, this routine is a separate archive object.  This
 * minimizes the amount of code carried around in statically linked binaries.
 *
 * This function returns -1 on error, or 0 on success.
 */
int tlspool_pin_service (char *path, uint32_t regflags, int responsetimeout_usec, void (*cb) (pinentry_t *entry, void *data), void *data);


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
		uint8_t *ctlkey);


/* Fetch a configuration variable value from the configuration file.  This is not
 * an efficient procedure, at best suited for startup of tools or daemons; it
 * will iterate over the config file until it reads the desired value.  The value
 * returned is allocated and should be freed by the caller using free().
 *
 * When cfgfile is NULL, the environment variable TLSPOOL_CONFIGFILE is
 * tried first, followed by the default setting from the macro 
 * TLSPOOL_DEFAULT_SOCKET_PATH as defined in <tlspool/starttls.h>.
 *
 * The value returned is NULL when the variable is not found, including when this
 * is due to errors such as not being able to open the file.
 */
char *tlspool_configvar (char *cfgfile, char *varname);


#ifdef __cplusplus
}
#endif


#endif // TLSPOOL_STARTTLS_H
