/* tlspool/ctlkey.c -- Control Key Registry
 *
 * The control key registry is a tree-shaped storage structure for ctlkey
 * values.  Basically, a pthread registers its control key for as long as
 * it is open to external parties claiming it; a claim will be translated
 * to a SIGINT to the registering pthread, which will leave its pselect()
 * and add the newly offered file descriptor.
 *
 * This tree remains balanced without doing much for it; it blindly assumes
 * that a ctlkey is a random binary string, which means that it will be
 * evenly scattered on average.  This is an explanation of why this registry
 * is lazy, and makes no extra effort to achieve balancing.
 *
 * The caller is expected to allocate (on its stack, presumably) a structure
 * for the administration of nodes in this tree.  Each node can have up to
 * 16 references to further details.  Leaf nodes can be NULL, which signals
 * that the stored pthread_t is the value sought.  Note that there is no such
 * thing as an invalid pthread_t 
 *
 * Finally, ctlkey values must be unique, which is normally the case when
 * 16 bytes are generated randomly.  The theoretic chance of a clash is
 * dealt with by reporting back an error.  With 16 bytes or 32 nibbles,
 * there are at most 32 levels of 16 branches in the ctlkeynode, and the
 * equality at 32 levels means that a clash was found.
 *
 * From: Rick van Rein <rick@openfortress.nl>
 */

#include "whoami.h"

#include <stdlib.h>
#include <fcntl.h>
#include <assert.h>
#include <errno.h>
#include <string.h>

#include <pthread.h>

#include <tlspool/internal.h>


/* The root entry is the initial node for the search tree.  It refers to
 * itself, but its address is treated as a special value, similar to NULL.
 */
static struct ctlkeynode *rootnode = NULL;

/* The ctlkey registry must be locked before it is read, or written.
 */
static pthread_mutex_t ctlkey_registry_lock = PTHREAD_MUTEX_INITIALIZER;

/* The ctlkey_signalling_fd is a file descriptor that can be listened to in
 * poll() with revents==0; it will signal an error if it is closed.  The file
 * is in fact an open file descriptor for /dev/null and it will be replaced
 * by a new one in this variable before it is closed.  The closing however,
 * ensures that the poll() is interrupted and interrogation of changed
 * conditions, notably reattahed file descriptors, can be tried.
 *
 * FORK!=DETACH marks lines that were defined to signal detaching ctlfd to
 * poll() statements by closing an fd.  It was inefficient and potentially
 * subject to race conditions.  The separation of FORK and DETACH made sense
 * from a conceptual viewpoint, and DETACH need not be notified to the poll()
 * statements whereas FORK can be done only during the STARTTLS exchange.
 * So, there is no further need for this signalling facility, as it appears
 * now; the code is merely here in case we might want to permit FORK later
 * in the command flow, and perhaps a reverse JOIN statement.  At the moment,
 * that is not considered helpful. 
 */
//FORK!=DETACH// int ctlkey_signalling_fd = -1;


/* A lock on the signalling_fd variable.
 */
//FORK!=DETACH// static pthread_mutex_t signalling_fd_lock = PTHREAD_MUTEX_INITIALIZER;


/* Raise the signal of the signalling_fd.  This requires the reliant poll()
 * operations to call ctlkey_signalling_fd() again -- unless of course, they
 * are supplied with a real controlling file descriptor, for which this is
 * just a substitute.
 */
//FORK!=DETACH// void ctlkey_signalling_raise (void) {
//FORK!=DETACH// 	int toclose;
//FORK!=DETACH// 	assert (pthread_mutex_lock (&signalling_fd_lock) == 0);
//FORK!=DETACH// 	toclose = ctlkey_signalling_fd;
//FORK!=DETACH// 	ctlkey_signalling_fd = open ("/dev/null", O_RDWR);
//FORK!=DETACH// 	close (toclose);	// Sends the "signal" to all interested poll()
//FORK!=DETACH// 	pthread_mutex_unlock (&signalling_fd_lock);
//FORK!=DETACH// }
	

/* Register a ctlkey and return 0 if it was successfully registered.  The
 * only reason for failure would be that the ctlkey is already registered,
 * which signifies an extremely unlikely clash -- or a program error by
 * not using properly scattered random sources.  The provided ctlfd may
 * be -1 to signal it is detached.  The forked flag should be non-zero
 * to indicate that this is a forked connection.
 */
int ctlkey_register (uint8_t *ctlkey, struct ctlkeynode *ckn, enum security_layer sec, pool_handle_t ctlfd, int forked) {
	int i;
	int todo;
	struct ctlkeynode **nodepp;
	assert (pthread_mutex_lock (&ctlkey_registry_lock) == 0);
	nodepp = &rootnode;
	while (*nodepp) {
		int cmp = memcmp (ctlkey, (*nodepp)->ctlkey, TLSPOOL_CTLKEYLEN);
		if (cmp == 0) {
			/* Value already known, clash detected */
			pthread_mutex_unlock (&ctlkey_registry_lock);
			return -1;
		} else if (cmp < 0) {
			nodepp = & (*nodepp)->lessnode;
		} else {
			nodepp = & (*nodepp)->morenode;
		}
	}
	ckn->lessnode = NULL;
	ckn->morenode = NULL;
	memcpy (ckn->ctlkey, ctlkey, sizeof (ckn->ctlkey));
	ckn->security = sec;
	ckn->ctlfd = ctlfd;
	ckn->forked = forked? 1: 0;
	*nodepp = ckn;
	pthread_mutex_unlock (&ctlkey_registry_lock);
	return 0;
}

/* Remove a registered cltkey value from th registry.  This is the most
 * complex operation, as it needs to merge the subtrees.
 *
 * This function returns non-zero iff it actually removed a node.  This
 * is useful because there may be other places from which this function
 * is called automatically.  Generally, the idea is to use a construct
 *	if (ctlkey_unregister (...)) {
 *		free (...);
 *      }
 *
 * TODO: Lazy initial implementation, entirely unbalanced; insert the
 * complete morenode under the highest lessnode that is NULL.
 */
void _ctlkey_unregister_nodepp (struct ctlkeynode **nodepp) {
	// This implementation changes *nodepp and may change child nodes
	// Higher-up nodes are not changed though
//DEBUG// fprintf(stderr, "Actually removing node %lx, ctlkey %02x %02x %02x %02x...\n", (long) (intptr_t) *nodepp, (*nodepp)->ctlkey [0], (*nodepp)->ctlkey [1], (*nodepp)->ctlkey [2], (*nodepp)->ctlkey [3]);
	struct ctlkeynode *subtreeless, *subtreemore;
	subtreeless = (*nodepp)->lessnode;
	subtreemore = (*nodepp)->morenode;
	(*nodepp)->lessnode = NULL;
	(*nodepp)->morenode = NULL;
	*nodepp = subtreeless;
	while (*nodepp) {
		nodepp = & (*nodepp)->morenode;
	}
	*nodepp = subtreemore;
//DEBUG// fprintf(stderr,"Node removal succeeded\n");
}
int ctlkey_unregister (uint8_t *ctlkey) {
	struct ctlkeynode **nodepp;
	int cmp = 1;
	assert (pthread_mutex_lock (&ctlkey_registry_lock) == 0);
	nodepp = &rootnode;
	while (*nodepp != NULL) {
		cmp = memcmp (ctlkey, (*nodepp)->ctlkey, TLSPOOL_CTLKEYLEN);
		if (cmp == 0) {
			/* Found the right node */
			_ctlkey_unregister_nodepp (nodepp);
			break;
		} else if (cmp < 0) {
			nodepp = & (*nodepp)->lessnode;
		} else {
			nodepp = & (*nodepp)->morenode;
		}
	}
	/* If not found, simply ignore */
	pthread_mutex_unlock (&ctlkey_registry_lock);
	return (cmp == 0);
}

/* Find a ctlkeynode based on a ctlkey.  Returns NULL if not found.
 * 
 * The value returned is the registered structure, meaning that any context
 * to the ctlkeynode returned can be relied upon.
 *
 * This also brings a responsibility to lock out other uses of the structure,
 * which means that a non-NULL return value must later be passed to a function
 * that unlocks the resource, ctlkey_unfind().
 */
struct ctlkeynode *ctlkey_find (uint8_t *ctlkey, enum security_layer sec, pool_handle_t ctlfd) {
	struct ctlkeynode *ckn;
	//
	// Claim unique access; this lock survives until cltkey_unfind()
	// if a non-NULL ctlkeynode is returned
	assert (pthread_mutex_lock (&ctlkey_registry_lock) == 0);
	//
	// Search through the tree of registered ctlkeynode structures
	ckn = rootnode;
	while (ckn != NULL) {
		int cmp = memcmp (ctlkey, ckn->ctlkey, TLSPOOL_CTLKEYLEN);
		if (cmp == 0) {
			/* Found the right node */
			if (ckn->ctlfd < 0) {
				ckn = NULL;	// Connection not under control
			} else if (ckn->ctlfd != ctlfd) {
				ckn = NULL;	// Connection is not yours to find
			} else if (ckn->security != sec) {
				ckn = NULL;	// Connection is not of right type
			} else {
				break;		// Found, so terminate loop
			}
			break;		 // Final result, so terminate loop
		} else if (cmp < 0) {
			ckn = ckn->lessnode;
		} else {
			ckn = ckn->morenode;
		}
	}
	//
	// Return the final node in ckn; hold the lock if it is non-NULL
	if (ckn == NULL) {
		pthread_mutex_unlock (&ctlkey_registry_lock);
	}
	return ckn;
}

/* Free a ctlkeynode that was returned by ctlkey_find().  This function also
 * accepts a NULL argument, though those need not be passed through this
 * function as is the case with the non-NULL return values.
 *
 * The need for this function arises from the need to lock the structure, in
 * avoidance of access to structures that are being unregistered in another
 * thread.
 */
void ctlkey_unfind (struct ctlkeynode *ckn) {
	//
	// Free the lock held after ctlkey_find() -- which is not locked when
	// the function returned NULL (we explicitly support that return value
	// here because it can help to simplify code using these functions,
	// and lead to better readable code with less oversights of unlocking
	if (ckn != NULL) {
		pthread_mutex_unlock (&ctlkey_registry_lock);
	}
}


/* Detach the given ctlkey, assuming it has clientfd as control connection.
 */
void ctlkey_detach (struct command *cmd) {
	uint8_t *ctlkey = cmd->cmd.pio_data.pioc_control.ctlkey;
	int todo;
	int tlserrno;
	char *errstr;
	struct ctlkeynode **nodepp;
	assert (pthread_mutex_lock (&ctlkey_registry_lock) == 0);
	nodepp = &rootnode;
	tlserrno = ENOENT;
	errstr = "Unknown control key could not detach";
	while (*nodepp != NULL) {
		int cmp = memcmp (ctlkey, (*nodepp)->ctlkey, TLSPOOL_CTLKEYLEN);
		if (cmp == 0) {
			/* Found the right node */
			if ((*nodepp)->ctlfd == INVALID_POOL_HANDLE) {
				tlserrno = EBUSY;
				errstr = "Connection not under control";
			} else if ((*nodepp)->ctlfd == cmd->clientfd) {
				(*nodepp)->ctlfd = INVALID_POOL_HANDLE;
				//FORK!=DETACH// ctlkey_signalling_raise ();
				tlserrno = 0;
				errstr = NULL;
			} else {
				tlserrno = EPERM;
				errstr = "Connection is not yours to detach";
			}
			break;
		} else if (cmp < 0) {
			nodepp = & (*nodepp)->lessnode;
		} else {
			nodepp = & (*nodepp)->morenode;
		}
	}
	/* If not found, tlserrno==ENOENT falls through */
	pthread_mutex_unlock (&ctlkey_registry_lock);
	// Send the error back -- or success if tlserrno==0
	send_error (cmd, tlserrno, errstr);
}


/* Reattach to the given ctlkey, and set the clientfd as control connection.
 */
void ctlkey_reattach (struct command *cmd) {
	uint8_t *ctlkey = cmd->cmd.pio_data.pioc_control.ctlkey;
	int todo;
	int tlserrno;
	char *errstr;
	struct ctlkeynode **nodepp;
	assert (pthread_mutex_lock (&ctlkey_registry_lock) == 0);
	nodepp = &rootnode;
	tlserrno = ENOENT;
	errstr = "Unknown control key could not reattach";
	while (*nodepp != NULL) {
		int cmp = memcmp (ctlkey, (*nodepp)->ctlkey, TLSPOOL_CTLKEYLEN);
		if (cmp == 0) {
			/* Found the right node */
			if ((*nodepp)->ctlfd == INVALID_POOL_HANDLE) {
				(*nodepp)->ctlfd = cmd->clientfd;
				//FORK!=DETACH// ctlkey_signalling_raise ();
				tlserrno = 0;
				errstr = NULL;
			} else {
				tlserrno = EBUSY;
				errstr = "Connection already under control";
			}
			break;
		} else if (cmp < 0) {
			nodepp = & (*nodepp)->lessnode;
		} else {
			nodepp = & (*nodepp)->morenode;
		}
	}
	/* If not found, tlserrno==ENOENT falls through */
	pthread_mutex_unlock (&ctlkey_registry_lock);
	// Send the error back -- or success if tlserrno==0
	send_error (cmd, tlserrno, errstr);
}

/* Look through the ctlkey registry, to find sessions that depend on a closing
 * control connection meaning that they cannot survive it being closed;
 * those entries will be unregistered and deallocated ; this is used when a
 * client socket closes its link to the TLS Pool.
 *
 * This implementation closes all entries whose ctlfd matches; this is needed
 * for detached nodes that have been reattached.  Nodes that are attached
 * will usually be removed before they hit this routine, which is also good.
 *
 * Note that detached keys are (by definition) protected against this cleanup
 * procedure; however, when their TLS connection breaks down, they too will
 * be cleaned up.  Note that detaching is not done before the TLS handshake
 * is complete.
 */
static void _ctlkey_close_ctlfd_recurse (pool_handle_t clisox, struct ctlkeynode **nodepp) {
	struct ctlkeynode *node = *nodepp;
	if (node == NULL) {
		return;
	}
	_ctlkey_close_ctlfd_recurse (clisox, &node->lessnode);
	_ctlkey_close_ctlfd_recurse (clisox, &node->morenode);
	if (node->ctlfd == clisox) {
		// At this point, subnodes may be removed and juggled,
		// but we can still rely on unchanged (*nodepp) == node
		assert (*nodepp == node);
//DEBUG// fprintf(stderr,"Unregistering control key (automatically, as controlling fd closes)\n");
		if (node->forked) {
			node->ctlfd = INVALID_POOL_HANDLE;
		} else {
			_ctlkey_unregister_nodepp (nodepp);
			// Now we know that *nodepp has changed, it is no longer
			// pointing to node (so we may remove it).
			// No changes have been made higher up though, so
			// recursion assumptions are still valid; see
			// _ctlkey_unregister_nodepp() for this assumption.
			free (node);
		}
	}
}
void ctlkey_close_ctlfd (pool_handle_t clisox) {
	assert (pthread_mutex_lock (&ctlkey_registry_lock) == 0);
	_ctlkey_close_ctlfd_recurse (clisox, &rootnode);
	pthread_mutex_unlock (&ctlkey_registry_lock);
}


/* Setup the ctlkey registry; notably, allocate the ctlkey_signalling_fd.
 */
void setup_ctlkey (void) {
	//FORK!=DETACH// ctlkey_signalling_fd = open ("/dev/null", O_RDWR);
}

/* Cleanup the ctlkey registry.
 */
void cleanup_ctlkey (void) {
	//FORK!=DETACH// int toclose = ctlkey_signalling_fd;
	//FORK!=DETACH// ctlkey_signalling_fd = -1;
	//FORK!=DETACH// close (toclose);
}
