/* tlspool/lidentry.c -- A client of the TLS Pool that can choose localids. */

#include "whoami.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <pthread.h>
#include <assert.h>

#include <unistd.h>
#include <syslog.h>
#include <time.h>

#include <errno.h>
#include <com_err.h>
#include <errortable.h>

#include <tlspool/internal.h>
#ifndef WINDOWS_PORT
#include <sys/socket.h>
#include <sys/un.h>
#endif /* WINDOWS_PORT */


/* The localid entry procedure permits registration for LIDENTRY callbacks.
 * When a localid is needed, the existing callback is used to ask for one.
 * While the collback is being processed, there could be a danger that another
 * process claims this somewhat-senstive privilege.  To avoid that, the previous
 * requester has the advantage of being the only one to register up to a
 * timeout that it included in the original request.  This mechanism is
 * pragmatic, in that it frees up the privilege after some time, while still
 * locking the privilege for a time that suits the original requester.
 *
 * The lidentry_lock is used to protect access to the following fields, and
 * effectively makes operations on it atomic.
 *
 * The lidentry_cmd holds a waiting LIDENTRY registration that would love to
 * be used in a callback procedure.  As soon as that happens, the entry is
 * reset to NULL to indicate that there is no current LIDENTRY registration.
 *
 * The lidentry_client holds the clientfd of the last LIDENTRY command that
 * registered, even after the lidentry_cmd has been reset to NULL.
 *
 * The lidentry_rereg_timeout is set to the seconds sinds the Epoch after which
 * the unique position of the lidentry_client ends.  It is initially set to
 * 0 to immediately permit the first LIDENTRY registration attempt, and it
 * will be set to the current time plus the specified timeout in the command
 * that is being used as a callback.
 *
 * The values of lidentry_regflags and lidentry_timeout are taken from the
 * field flags and timeout during processing of a PIOC_LIBENTRY_REGISTER_V2.
 */
static pthread_mutex_t lidentry_lock = PTHREAD_MUTEX_INITIALIZER;
static struct command *lidentry_cmd = NULL;
static pool_handle_t lidentry_client = INVALID_POOL_HANDLE;
static time_t lidentry_rereg_timeout = 0;
static uint32_t lidentry_regflags;	// Setup during registration
static uint32_t lidentry_timeout;	// Setup during registration (#sec)
static pthread_cond_t lidentry_cbseq = PTHREAD_COND_INITIALIZER;
static int lidentry_cbseq_claimed = 0;      // Is the callback sequence claimed?
static pthread_t lidentry_cbseq_claimedby;  // If claimed, then by which thread?


/* Internal claim routine for the callback sequence resource.  This will wait
 * until either the resource is held by the calling thread, or until it is
 * certainly impossible -- because no program is registered for LID entry and
 * any prior registration has timed out.
 *
 * The returned value is 1 when the claim succeeds, or 0 on failure; note
 * that failure can only occur if no LID entry program is registered, and
 * the timeout of the previous registration has also passed.
 *
 * When successful, the "lidcmd" pointer is filled atomically with the
 * lidentry_cmd value, which is guaranteed to not be NULL.
 */
static success_t lidentry_cbseq_claim (struct command **lidcmd) {
	int retval;
	//
	// Return immediately when no command has been registered
	assert (pthread_mutex_lock (&lidentry_lock) == 0);
	//
	// Now be pushy, until the LID entry can/has be claimed for me
	while (lidentry_cbseq_claimed && !pthread_equal (lidentry_cbseq_claimedby, pthread_self ())) {
		time_t now = time (NULL);
		struct timespec ts;
		if (now >= lidentry_rereg_timeout) {
			// Expired, so accept anyway
			break;
		}
		memset (&ts, 0, sizeof (ts));
		ts.tv_sec = lidentry_rereg_timeout;
		//
		// During _claimedby, lidentry_cmd may be NULL: we should wait
		pthread_cond_timedwait (&lidentry_cbseq, &lidentry_lock, &ts);
	}
	//
	// Now, either:
	//  - _claimed == 0, or
	//  - _claimed == 1 and _claimedby == pthread_self ()
	// We may now observe lidentry_cmd; NULL would actually mean "none"
	*lidcmd = lidentry_cmd;
	if (*lidcmd == NULL) {
		//
		// Handle absense of registered LID entry service, as well as
		// temporary conditions prior to (re)reg of timed-out clients
		retval = 0;
	} else {
		//
		// Claim the lidentry callback sequence (idempotent change)
		lidentry_cbseq_claimed = 1;
		lidentry_cbseq_claimedby = pthread_self ();
		retval = 1;
	}
	pthread_mutex_unlock (&lidentry_lock);
	return retval;
}


/* Internal release routine for the callback sequence resource.  This is
 * used to signal any waiting threads about their chance to get hold of
 * the sequence resource.  It is assumed that the resource has been claimed,
 * or is otherwise ready for release.
 *
 * TODO: We're broadcasting, which is a bit overzealous; perhaps we can
 *       keep it down and only signal a single waiting thread.
 */
static void lidentry_cbseq_release (void) {
	//NONEED// assert (pthread_utex_lock (&lidentry_lock) == 0);
	//ASSUMED// if (lidentry_cbseq_claimed && pthread_equal (lidentry_cbseq_claimedby, pthread_self ())) {
		lidentry_cbseq_claimed = 0;
		pthread_cond_broadcast (&lidentry_cbseq);
	//ASSUMED// }
	//NONEED// pthread_mutex_unlock (&lidentry_lock);
}


/* Register an application socket as one that is willing to process LID entry
 * requests.  The file descriptor may also be used for other functions,
 * so it is only safe to use as a sending channel.  Registration is just
 * for one try, after which the application protocol will let it re-register.
 */
void register_lidentry_command (struct command *cmd) {
	int error = 0;
	assert (pthread_mutex_lock (&lidentry_lock) == 0);
	if (lidentry_cmd == NULL) {
		time_t now = time (NULL);
		// There is actually a need for a LID entry command to register
		if (lidentry_client == cmd->clientfd) {
			// This command came from the same client as last time
			lidentry_cmd = cmd;
			tlog (TLOG_USER | TLOG_UNIXSOCK, LOG_NOTICE, "Registered privileged command for LID entry");
		} else {
			// New LID entry clients await the last one's timeout
			if (now > lidentry_rereg_timeout) {
				// The wait for new client access has passed
				lidentry_cmd = cmd;
				lidentry_client = cmd->clientfd;
				lidentry_regflags = 0;
				tlog (TLOG_USER | TLOG_UNIXSOCK, LOG_NOTICE, "Registered new client's command for LID entry");
			} else {
				// The previous client still is privileged
				error = 1;
				tlog (TLOG_USER | TLOG_UNIXSOCK, LOG_NOTICE, "Refused LID entry command from other client");
			}
		}
		if (error == 0) {
			lidentry_regflags |= cmd->cmd.pio_data.pioc_lidentry.flags;
			lidentry_timeout = cmd->cmd.pio_data.pioc_lidentry.timeout;
			lidentry_rereg_timeout = now + lidentry_timeout;
		}
	} else {
		// There already is a LIDENTRY registration
		error = 1;
		tlog (TLOG_USER | TLOG_UNIXSOCK, LOG_NOTICE, "Refused extra LID entry command");
	}
	pthread_mutex_unlock (&lidentry_lock);
	if (error) {
		send_error (cmd, E_TLSPOOL_LIDENTRY_NOT_VACANT,
				"TLS Pool has no vacancy for localid selection");
		return;
	}
}


/* Drop any LIDENTRY requests related to the given file descriptor, which is
 * being closed.  The LIDENTRY facility is freed up immediately for the next
 * requestor.
 */
void lidentry_forget_clientfd (pool_handle_t fd) {
	assert (pthread_mutex_lock (&lidentry_lock) == 0);
printf ("DEBUG: forgetting LID entry clientfd %d (if it is %d and not -1)\n", fd, lidentry_client);
	// Only respond when the current client wants to be forgotten
	if (fd == lidentry_client) {
		// No response possible.  Service reclaims for cmd pooling
		lidentry_cmd = NULL;
		// Immediately free up for any new LIDENTRY request
		lidentry_rereg_timeout = 0;
		// The following is needless but more consistent with restart
		lidentry_client = INVALID_POOL_HANDLE;
		// Forcefully free the callback sequence claim
		lidentry_cbseq_claimed = 0;
		// Note: Callbacks waiting on fd should receive an ERROR reply
		//       so we don't interfere with running threads down here
	}
	pthread_mutex_unlock (&lidentry_lock);
}


/* Check if the localid registration permits skipping of the given database
 * entry.  Such skips mean that the database entry on its own may fulfill the
 * completion of the localid value.  This takes into account all the
 * PIOF_LIDENTRY_SKIP_xxx flags registered by the client.
 *
 * The levels_up value counts 2 per step for domain names, and 1 per step for
 * user@domain identifiers.  So, with 0 for the concrete value, the low bit
 * indicates removal of a username and all higher bits refer to the steps up
 * in terms of a domain name.
 *
 * The at_root value indicates if this domain name is at the domain root,
 * irrespective of the existence or removal of usernames.
 *
 * This command is not run within a lock that protects against race conditions
 * related to registration of lidentry programs.  The reasoning is that the
 * re-registration infrastructure including timeouts suffices to keep these
 * programs registered once they have been, and when a program registers anew
 * there are bound to be such race condition opportunities.  It is useful to
 * have this property, as it also means that no lock is acquired no LID entry
 * for just checking if a database entry may just skip the callbacks.
 */
success_t lidentry_database_mayskip (int levels_up, int at_root) {
	int retval = -1;  // Meaning, undecided
	uint32_t regfl;
	//SEE-COMMENT// assert (pthread_mutex_lock (&lidentry_lock) == 0);
	if (lidentry_cmd == NULL) {
		retval = 1;  // Callback timed out: skip ok
	}
	regfl = lidentry_regflags;
	//SEE-COMMENT// pthread_mutex_unlock (&lidentry_lock);
	if (retval != -1) {
		; // retval has been decided on, keep it as it as
	} else if (regfl & PIOF_LIDENTRY_SKIP_DBENTRY) {
		retval = 1;  // Assume success but AND the various skip checks
		if (regfl & PIOF_LIDENTRY_SKIP_DOMAIN_SUB) {
			retval = 0;  // Assume failure but OR these two checks
			if ((regfl & PIOF_LIDENTRY_SKIP_DOMAIN_SAME ) && ((levels_up >> 1) == 0)) {
				retval = 1;
			}
			if ((regfl & PIOF_LIDENTRY_SKIP_DOMAIN_ONEUP) && ((levels_up >> 1) == 1)) {
				retval = 1;
			}
			// retval is now _SAME | _ONEUP, or equivalently, DOMAIN_SUB
			// and can now proceed to (...|...) & ... & ... & ...
		}
		if (regfl & PIOF_LIDENTRY_SKIP_USER) {
			if (levels_up & 1) {
				retval = 0;
			}
		}
		if (regfl & PIOF_LIDENTRY_SKIP_NOTROOT) {
			if (at_root) {
				retval = 0;
			}
		}
	} else {
		retval = 0;
	}
	return retval;
}


/* Implement the function for localid callback with a database entry, as they
 * precede the localid inquiry callback.
 *
 * The maxlevels value counts 1 per step for domain names, and 1 per step for
 * user@domain identfiers.  The value 0 indicates the concrete value, which
 * is submitted in the remoteid parameter.  Note that maxlevels differs from
 * the levels_up parameter to lidentry_database_mayskip() in that domain names
 * are only half the value.
 *
 * This setup will claim the callback program, because a sequence of messages
 * must now be sent to it.  Without this sequence, the callback program would
 * get confusing mixtures of messages.  This implies a requirement to also
 * invoke lidentry_inquiry_callback(), as this is where any such lock will be
 * released; it is always the last in such sequences of messages.
 */
success_t lidentry_database_callback (char *remoteid, int maxlevels, char *localid) {
	struct command *cmd;
	int retval;
printf ("DEBUG: lidentry_database_callback() got localid=%s\n", localid);
	retval = lidentry_cbseq_claim (&cmd);  // Idempotent claim
	if (retval != 1) {
		// Did not get the cbseq_claim, presumably in lieu of listener
printf ("DEBUG: lidentry_database_callback() does not hold the cbseq_claim\n");
		return retval;
	}
	//
	// Return immediately when database callbacks are not requested
	if ((lidentry_regflags & PIOF_LIDENTRY_WANT_DBENTRY) == 0) {
printf ("DEBUG: lidentry_database_callback() was asked not to return DBENTRY\n");
		return 1;
	}
	//
	// Fill the command structure with the database feedback information
	lidentry_rereg_timeout = time (NULL) + lidentry_timeout;
	cmd->cmd.pio_cmd = PIOC_LIDENTRY_CALLBACK_V2;
	cmd->cmd.pio_data.pioc_lidentry.flags = PIOF_LIDENTRY_DBENTRY | (lidentry_regflags & PIOF_LIDENTRY_REGFLAGS);
	cmd->cmd.pio_data.pioc_lidentry.maxlevels = maxlevels;
	cmd->cmd.pio_data.pioc_lidentry.timeout = lidentry_rereg_timeout;
	memset (cmd->cmd.pio_data.pioc_lidentry.localid, 0, 128);
	memset (cmd->cmd.pio_data.pioc_lidentry.remoteid, 0, 128);
	strncpy (cmd->cmd.pio_data.pioc_lidentry.remoteid, remoteid, 127);
	strncpy (cmd->cmd.pio_data.pioc_lidentry.localid , localid , 127);
	//
	// Send the callback command; ignore any response
	tlog (TLOG_UNIXSOCK, LOG_DEBUG, "Calling send_callback_and_await_response() with database lidentry information");
	lidentry_cmd = NULL;
	cmd = send_callback_and_await_response (cmd, lidentry_rereg_timeout);
	if (cmd) {
		tlog (TLOG_UNIXSOCK, LOG_DEBUG, "Returnd send_callback_and_await_response() from database lidentry information");
		//
		// Re-register callback command (or at least try to)
		cmd->cmd.pio_data.pioc_lidentry.timeout = lidentry_timeout;
		register_lidentry_command (cmd);
	} else {
		tlog (TLOG_UNIXSOCK, LOG_DEBUG, "Timeout send_callback_and_await_response() from database lidentry information");
	}
	return (cmd != NULL);
}


/* Implement the function for localid inquiry callback.  This function will
 * contact the currently set LID handler connection.
 *
 * Upon returning failure, the localid and flags have not been changed.  This
 * means that it may be possible for the caller to setup defaults and process
 * the outcome regardless of success or failure of this function.
 */
success_t lidentry_inquiry_callback (char remoteid [128], int maxlevels, char localid [128], uint32_t *flags) {
	struct command *cmd;
	int retval;
	//
	// Return trivially when no command has registered; keep localid as is
	//TODO// Claim the callback sequence resource (or confirm holding it)
	retval = lidentry_cbseq_claim (&cmd);  // Idempotent claim
	if (retval != 1) {
		tlog (TLOG_USER, LOG_DEBUG, "No LID entry command registered, so no callback made (unchanged localid)");
		return 1;
	}
	//
	// Fill the command structure with the database feedback information
	lidentry_rereg_timeout = time (NULL) + lidentry_timeout;
	cmd->cmd.pio_cmd = PIOC_LIDENTRY_CALLBACK_V2;
	cmd->cmd.pio_data.pioc_lidentry.flags = (lidentry_regflags & PIOF_LIDENTRY_REGFLAGS); // not.PIOF_LIDENTRY_DBENTRY
	cmd->cmd.pio_data.pioc_lidentry.maxlevels = maxlevels;
	cmd->cmd.pio_data.pioc_lidentry.timeout = lidentry_rereg_timeout;
	memcpy (cmd->cmd.pio_data.pioc_lidentry.localid, localid, 128);
	memset (cmd->cmd.pio_data.pioc_lidentry.remoteid, 0, 128);
	strncpy (cmd->cmd.pio_data.pioc_lidentry.remoteid, remoteid, 127);
	//
	// Send the callback command; ignore any response
	tlog (TLOG_UNIXSOCK, LOG_DEBUG, "Calling send_callback_and_await_response() with request for localid");
	lidentry_cmd = NULL;
printf ("DEBUG: Sent out clientfd=%d (should be %d)\n", cmd->clientfd, lidentry_client);
	cmd = send_callback_and_await_response (cmd, lidentry_rereg_timeout);
printf ("DEBUG: Got back clientfd=%d (should be %d)\n", cmd->clientfd, lidentry_client);
	if (!cmd) {
		tlog (TLOG_UNIXSOCK, LOG_DEBUG, "Timeout send_callback_and_await_response() from request for localid");
		retval = 0;
	} else {
		tlog (TLOG_UNIXSOCK, LOG_DEBUG, "Returnd send_callback_and_await_response() from request for localid");
		//
		// Process the result from the callback 
		if (cmd->cmd.pio_cmd != PIOC_LIDENTRY_CALLBACK_V2) {
			tlog (TLOG_UNIXSOCK, LOG_DEBUG, "Response holds no LID entry and so the callback reports failure");
			retval = 0;
		} else {
			cmd->cmd.pio_data.pioc_lidentry.localid [127] = '\0';
			tlog (TLOG_UNIXSOCK, LOG_DEBUG, "Response holds LID entry \"%s\"", cmd->cmd.pio_data.pioc_lidentry.localid);
			memcpy (localid , cmd->cmd.pio_data.pioc_lidentry.localid , 128);
			memcpy (remoteid, cmd->cmd.pio_data.pioc_lidentry.remoteid, 128);
			*flags = cmd->cmd.pio_data.pioc_lidentry.flags;
			retval = 1;
		}
		//
		// Re-register the command (or at least try to)
		cmd->cmd.pio_data.pioc_lidentry.timeout = lidentry_timeout;
		register_lidentry_command (cmd);
	}
	//
	// Free our hold on the callback sequence resource, broadcast it
	if (lidentry_cmd == cmd) {
		// Reduced chances of funny behaviour due to takeover async
		lidentry_cbseq_release ();
	}
	//
	// Report back to the caller
	return retval;
}


void setup_lidentry (void) {
	;	/* Nothing to do */
}

void cleanup_lidentry (void) {
	;	/* Nothing to do */
}

