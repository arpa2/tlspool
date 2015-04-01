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


#include <fcntl.h>
#include <assert.h>
#include <errno.h>

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
 * be -1 to signal it is not valid.
 */
int ctlkey_register (uint8_t *ctlkey, struct ctlkeynode *ckn, int ctlfd) {
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
	ckn->ctlfd = ctlfd;
	*nodepp = ckn;
	pthread_mutex_unlock (&ctlkey_registry_lock);
	return 0;
}

/* Remove a registered cltkey value from th registry.  This is the most
 * complex operation, as it needs to merge the subtrees.
 * TODO: Lazy initial implementation, entirely unbalanced; insert the
 * complete morenode under the highest lessnode NULL.
 */
void ctlkey_unregister (uint8_t *ctlkey) {
	struct ctlkeynode **nodepp;
	struct ctlkeynode *subtreeless, *subtreemore;
	assert (pthread_mutex_lock (&ctlkey_registry_lock) == 0);
	nodepp = &rootnode;
	while (*nodepp != NULL) {
		int cmp = memcmp (ctlkey, (*nodepp)->ctlkey, TLSPOOL_CTLKEYLEN);
		if (cmp == 0) {
			/* Found the right node */
			subtreeless = (*nodepp)->lessnode;
			subtreemore = (*nodepp)->morenode;
			(*nodepp)->lessnode = NULL;
			(*nodepp)->morenode = NULL;
			*nodepp = subtreeless;
			while (*nodepp) {
				nodepp = & (*nodepp)->morenode;
			}
			*nodepp = subtreemore;
			break;
		} else if (cmp < 0) {
			nodepp = & (*nodepp)->lessnode;
		} else {
			nodepp = & (*nodepp)->morenode;
		}
	}
	/* If not found, simply ignore */
	pthread_mutex_unlock (&ctlkey_registry_lock);
}


/* Dattach the given ctlkey, assuming it has clientfd as control connection.
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
			if ((*nodepp)->ctlfd < 0) {
				tlserrno = EBUSY;
				errstr = "Connection not under control";
			} else if ((*nodepp)->ctlfd == cmd->clientfd) {
				(*nodepp)->ctlfd = -1;
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
			if ((*nodepp)->ctlfd < 0) {
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

/* Look through the ctlkey registry, to find forked sessions; that is, sessions
 * that reference a control connection but that are not dependent on them for
 * survival; those entries will be detached; this is used when a client socket
 * closes the link to the TLS Pool.
 *
 * This implementation changes all entries whose ctlfd matches; sessions that
 * are not forked will terminate soon afterwards anyway.
 */
static void ctlkey_close_clientfd_recurse (int clisox, struct ctlkeynode *node) {
	if (node == NULL) {
		return;
	}
	if (node->ctlfd == clisox) {
		node->ctlfd = -1;
	}
	ctlkey_close_clientfd_recurse (clisox, node->lessnode);
	ctlkey_close_clientfd_recurse (clisox, node->morenode);
}
void ctlkey_close_clientfd (int clisox) {
	assert (pthread_mutex_lock (&ctlkey_registry_lock) == 0);
	ctlkey_close_clientfd_recurse (clisox, rootnode);
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
