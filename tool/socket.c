/* Socket utilities, including parsing and sockaddr juggling.
 *
 * Taken from the KXOVER project, and adapted somewhat.
 *
 * From: Rick van Rein <rick@openfortress.nl>
 */


#include "socket.h"

#include <stddef.h>
#include <stdlib.h>
#include <limits.h>
#include <assert.h>
#include <string.h>

#include <unistd.h>
#include <fcntl.h>


#ifdef DEBUG
#  include <stdio.h>
#  define DPRINTF printf
#else
#  define DPRINTF(...)
#endif


/* Given a socket address, determine its length.
 *
 * This function does not fail.
 *
 * TODO:inline
 */
socklen_t sockaddrlen (const struct sockaddr *sa) {
	assert ((sa->sa_family == AF_INET6) || (sa->sa_family == AF_INET));
	if (sa->sa_family == AF_INET6) {
		return sizeof (struct sockaddr_in6);
	} else {
		return sizeof (struct sockaddr_in );
	}
}


/* Store a raw address from a given family in a socket address,
 * together with a port that may be set to 0 as a catch-all.
 */
bool socket_address (sa_family_t af, uint8_t *addr, uint16_t portnr, struct sockaddr *sa) {
	sa->sa_family = af;
	memset (sa, 0, sockaddrlen (sa));
	sa->sa_family = af;
	switch (af) {
	case AF_INET6:
		memcpy (&((struct sockaddr_in6 *) sa)->sin6_addr, addr, 16);
		((struct sockaddr_in6 *) sa)->sin6_port = htons (portnr);
		return true;
	case AF_INET:
DPRINTF ("DEBUG: socket address (%d.%d.%d.%d, %d)\n", addr [0], addr [1], addr [2], addr [3], portnr);
		memcpy (&((struct sockaddr_in  *) sa)->sin_addr,  addr,  4);
		((struct sockaddr_in  *) sa)->sin_port  = htons (portnr);
		return true;
	default:
		break;
	}
	kxerrno = EINVAL;
	return false;
}


/* Parse an address and port, and store them in a sockaddr of
 * type AF_INET or AF_INET6.  The space provided is large enough
 * to hold either, as it is defined as a union.
 *
 * The opt_port may be NULL, in which case the port is set to 0
 * in the returned sockaddr; otherwise, its value is rejected
 * if it is 0.
 *
 * We always try IPv6 address parsing first, but fallback to
 * IPv4 if we have to, but that fallback is deprecated.  The
 * port will be syntax-checked and range-checked.
 *
 * Return true on success, or false with kxerrno set on error.
 */
bool socket_parse (char *addr, char *opt_port, struct sockaddr *out_sa) {
	//
	// Optional port parsing
	uint16_t portnr = 0;
	if (opt_port != NULL) {
		long p = strtol (opt_port, &opt_port, 10);
		if (*opt_port != '\0') {
			kxerrno = EINVAL;
			return false;
		}
		if ((p == LONG_MIN) || (p == LONG_MAX) || (p <= 0) || (p > 65535)) {
			/* errno is ERANGE */
			kxerrno = errno;
			return false;
		}
		portnr = (uint16_t) p;
	}
	//
	// IPv6 address parsing
	uint8_t raw_addr [16];
	switch (inet_pton (AF_INET6, addr, raw_addr)) {
	case 1:
		return socket_address (AF_INET6, raw_addr, portnr, out_sa);
	case 0:
		break;
	default:
		break;
	}
	//
	// IPv4 address parsing
	switch (inet_pton (AF_INET,  addr, raw_addr)) {
	case 1:
		return socket_address (AF_INET,  raw_addr, portnr, out_sa);
	case 0:
		break;
	default:
		break;
	}
	//
	// Report EINVAL as an error condition
	kxerrno = EINVAL;
	return false;
}


/* Open a connection as a client, to the given address.  Do not bind locally.
 *
 * Set contype to one SOCK_DGRAM, SOCK_STREAM or SOCK_SEQPACKET.
 *
 * The resulting socket is written to out_sox.
 *
 * Return true on success, or false with kxerrno set on failure.
 * On error, *out_sox is set to -1.
 */
bool socket_client (const struct sockaddr *peer, int contype, int *out_sox) {
	int sox = -1;
       	sox = socket (peer->sa_family, contype, 0);
	if (sox < 0) {
		goto fail;
	}
	if (connect (sox, peer, sockaddrlen (peer)) != 0) {
		goto fail;
	}
#ifdef WE_ARE_IN_KXOVER
	int soxflags = fcntl (sox, F_GETFL, 0);
	if (fcntl (sox, F_SETFL, soxflags | O_NONBLOCK) != 0) {
		goto fail;
	}
#endif
	*out_sox = sox;
	return true;
fail:
	*out_sox = -1;
	if (sox >= 0) {
		close (sox);
	}
	return false;
}


/* Open a listening socket as a server, at the given address.
 *
 * Set contype to one of SOCK_DGRAM, SOCK_STREAM or SOCK_SEQPACKET.
 *
 * The resulting socket is written to out_sox.
 *
 * Return true on success, or false with kxerrno set on failure.
 * On error, *out_sox is set to -1.
 */
bool socket_server (const struct sockaddr *mine, int contype, int *out_sox) {
	int sox = -1;
       	sox = socket (mine->sa_family, contype, 0);
	if (sox < 0) {
		goto fail;
	}
	if (bind (sox, mine, sockaddrlen (mine)) != 0) {
		goto fail;
	}
	if ((contype == SOCK_STREAM) || (contype == SOCK_SEQPACKET)) {
		if (listen (sox, 10) != 0) {
			goto fail;
		}
	}
#ifdef WE_ARE_IN_KXOVER
	int soxflags = fcntl (sox, F_GETFL, 0);
	if (fcntl (sox, F_SETFL, soxflags | O_NONBLOCK) != 0) {
		goto fail;
	}
#endif
	*out_sox = sox;
	return true;
fail:
	*out_sox = -1;
	if (sox >= 0) {
		close (sox);
	}
	return false;
}


