/* tlspool/pinentry.c -- Connect to the local tlspool and enter PINs. */

#include "whoami.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <pthread.h>
#include <assert.h>

#include <unistd.h>
#include <syslog.h>
#include <errno.h>
#include <time.h>

#include <tlspool/internal.h>

#ifdef WINDOWS_PORT
#include <winsock2.h>
#define sleep(secs) Sleep(secs)
#else /* WINDOWS_PORT */
#include <sys/socket.h>
#include <sys/un.h>
#endif /* WINDOWS_PORT */
#include <p11-kit/pkcs11.h>
#include <p11-kit/uri.h>


#ifdef FIXEDPIN
#define getpass(prompt) ( fprintf (stderr, "%s: %s\n", prompt, FIXEDPIN), FIXEDPIN )
#endif


/* The PIN entry procedure consists of a registration for PINENTRY callbacks.
 * When a PIN is needed, the existing callback is used to ask for one.
 * While the callback is being processed, there could be a danger that another
 * process claims this senstive privilege.  To avoid that, the previous
 * requester has the advantage of being the only one to register up to a
 * timeout that it included in the original request.  This mechanism is
 * pragmatic, in that it frees up the privilege after some time, while still
 * locking the privilege for a time that suits the original requester.
 *
 * The pinentry_lock is used to protect access to the following fields, and
 * effectively makes operations on it atomic.
 *
 * The pinentry_cmd holds a waiting PINENTRY registration that would love to
 * be used in a callback procedure.  As soon as that happens, the entry is
 * reset to NULL to indicate that there is no current PINENTRY registration.
 *
 * The pinentry_client holds the clientfd of the last PINENTRY command that
 * registered, even after the pinentry_cmd has been reset to NULL.
 *
 * The pinentry_timeout is set to the time (NULL) value after which
 * the unique position of the pinentry_client ends.  It is initially set to
 * 0 to immediately permit the first PINENTRY registration attempt, and it
 * will be set to the current time plus the specified timeout in the command
 * that is being used as a callback.
 */
static pthread_mutex_t pinentry_lock = PTHREAD_MUTEX_INITIALIZER;
static struct command *pinentry_cmd = NULL;
static pool_handle_t pinentry_client = INVALID_POOL_HANDLE;
static time_t pinentry_timeout = 0;


/*
 * Register an application socket as one that is willing to process PIN entry
 * requests.  The file descriptor may also be used for other functions,
 * so it is only safe to use as a sending channel.  Registration is just
 * for one try, after which the application protocol will let it re-register.
 */
void register_pinentry_command (struct command *cmd) {
	int error = 0;
	assert (pthread_mutex_lock (&pinentry_lock) == 0);
	if (!pinentry_cmd) {
		// There is actually a need for a PIN entry command to register
		if (pinentry_client == cmd->clientfd) {
			// This command came from the same client as last time
			pinentry_cmd = cmd;
			tlog (TLOG_PKCS11 | TLOG_USER | TLOG_UNIXSOCK, LOG_NOTICE, "Registered privileged command for PIN entry");
		} else {
			// New PIN entry clients await the last one's timeout
			time_t now = time (NULL);
			if (now > pinentry_timeout) {
				// The wait for new client access has passed
				pinentry_cmd = cmd;
				pinentry_client = cmd->clientfd;
				tlog (TLOG_PKCS11 | TLOG_USER | TLOG_UNIXSOCK, LOG_NOTICE, "Registered new client's command for PIN entry");
			} else {
				// The previous client still is privileged
				error = 1;
				tlog (TLOG_PKCS11 | TLOG_USER | TLOG_UNIXSOCK, LOG_NOTICE, "Refused PIN entry command from other client");
			}
		}
	} else {
		// There already is a PINENTRY registration
		error = 1;
		tlog (TLOG_PKCS11 | TLOG_USER | TLOG_UNIXSOCK, LOG_NOTICE, "Refused extra PIN entry command");
	}
	pthread_mutex_unlock (&pinentry_lock);
	if (error) {
		send_error (cmd, EBUSY, "Another PIN entry process is active");
		return;
	}
}


/* Drop any PINENTRY requests related to the given file descriptor, which is
 * being closed.  The PINENTRY facility is freed up immediately for the next
 * requestor.
 */
void pinentry_forget_clientfd (pool_handle_t fd) {
	assert (pthread_mutex_lock (&pinentry_lock) == 0);
	if (pinentry_client == fd) {
		// No response possible.  Service reclaims for cmd pooling
		pinentry_cmd = NULL;
		// Immediately free up for any new PINENTRY request
		pinentry_timeout = 0;
		// The following is needless but more consistent with restart
		pinentry_client = INVALID_POOL_HANDLE;
	}
	pthread_mutex_unlock (&pinentry_lock);
}


/* Implement a callback function for token insertion.  For now, this function
 * does not contact the user, but it might do that in future versions, using
 * a to-be-defined callback through the socket API.  Talk to me if you think
 * this is useful!
 */
success_t token_callback (const char *const label, unsigned retry) {
	int sleepsecs [4] = { 1, 2, 5, 5 };
	fprintf (stderr, "Please insert PKCS #11 token \"%s\"\n", label);
	sleep ((retry >= 4)? 10: sleepsecs [retry]);
	return 0;
}
 

/* A tool to copy the said number of characters from a PKCS #11 fixed-size
 * field to a NUL-terminated C-style string, without spaces to pad it and
 * with potentially one more position than given (for the NUL character).
 */
void p11cpy (char *cstr, CK_UTF8CHAR *p11str, int p11len) {
	memcpy (cstr, p11str, p11len);
	while ((p11len > 0) && (cstr [p11len-1] == ' ')) {
		p11len--;
	}
	cstr [p11len] = 0;
}

/*
 * Implement the generic function for PIN callback.  This function will
 * address the currently set PIN handler connection.
 */
success_t pin_callback (	int attempt,
				const char *token_url,
				const char *opt_prompt,
				char *pin,
				size_t pin_max) {
	struct command *cmd;
	int appsox;
	int retval = 1;
	P11KitUri *p11kituri;
	CK_TOKEN_INFO_PTR toktok;
	char *cfgpin;
	//
	// First try to find the PIN in the configuration file
	cfgpin = cfg_p11pin ();
	if ((cfgpin != NULL) && (*cfgpin) && (strlen (cfgpin) < pin_max)) {
		strcpy (pin, cfgpin);
		tlog (TLOG_PKCS11, LOG_DEBUG, "Returning configured PIN and OK from PIN entry");
		return 1;
	}
	//
	// Grab the current PINENTRY registration or report failure
	assert (pthread_mutex_lock (&pinentry_lock) == 0);
	cmd = pinentry_cmd;
	if (cmd != NULL) {
		tlog (TLOG_PKCS11 | TLOG_USER, LOG_DEBUG, "Using registered PIN entry command");
		// A PINENTRY command was registered
		pinentry_cmd = NULL;
		pinentry_timeout = time (NULL) + cmd->cmd.pio_data.pioc_pinentry.timeout_us / 1000000;
	} else {
		// There was no PINENTRY command registration
		//TODO// Wait (some time) for PINENTRY command to show up
		retval = 0;
	}
	pthread_mutex_unlock (&pinentry_lock);
	if (!retval) {
		tlog (TLOG_PKCS11 | TLOG_USER, LOG_DEBUG, "Returning failure from PIN entry");
		return retval;
	}
	//
	// Construct PIN ENTRY response, claim responses and send to the origin
	p11kituri = p11_kit_uri_new ();
	if (!p11kituri) {
		tlog (TLOG_PKCS11, LOG_CRIT, "Failed to allocate URI for PIN entry");
		return 0;
	}
	if (p11_kit_uri_parse (token_url, P11_KIT_URI_FOR_TOKEN, p11kituri) != P11_KIT_URI_OK) {
		p11_kit_uri_free (p11kituri);
		tlog (TLOG_PKCS11 | TLOG_USER, LOG_ERR, "Failed to parse URI for PIN entry");
		return 0;
	}
	toktok = p11_kit_uri_get_token_info (p11kituri);
	p11_kit_uri_free (p11kituri);
	if (!toktok) {
		tlog (TLOG_PKCS11 | TLOG_USER, LOG_ERR, "Failed to find URI token info for PIN entry");
		return 0;
	}
	p11cpy (cmd->cmd.pio_data.pioc_pinentry.token_manuf, toktok->manufacturerID, 32);
	p11cpy (cmd->cmd.pio_data.pioc_pinentry.token_model, toktok->model, 16);
	p11cpy (cmd->cmd.pio_data.pioc_pinentry.token_serial, toktok->serialNumber, 16);
	p11cpy (cmd->cmd.pio_data.pioc_pinentry.token_label, toktok->label, 32);
	cmd->cmd.pio_data.pioc_pinentry.attempt = attempt;
	strncpy (cmd->cmd.pio_data.pioc_pinentry.prompt,
			opt_prompt? opt_prompt: "Enter PIN: ",
			sizeof (cmd->cmd.pio_data.pioc_pinentry.prompt)-1);
	cmd->cmd.pio_data.pioc_pinentry.prompt [sizeof (cmd->cmd.pio_data.pioc_pinentry.prompt)-1] = '\0';
	//
	// Await response or timeout
	tlog (TLOG_UNIXSOCK, LOG_DEBUG, "Calling send_callback_and_await_response()");
	cmd = send_callback_and_await_response (cmd, 0);
	register_pinentry_command (cmd);
	tlog (TLOG_UNIXSOCK, LOG_DEBUG, "Returnd send_callback_and_await_response()");
	if ((cmd->cmd.pio_cmd != PIOC_PINENTRY_V2) || !*cmd->cmd.pio_data.pioc_pinentry.pin) {
		tlog (TLOG_PKCS11 | TLOG_USER, LOG_ERR, "Funny command or empty PIN code for PIN entry");
		return 0;
	}
	if (1 + strlen (cmd->cmd.pio_data.pioc_pinentry.pin) > pin_max) {
		tlog (TLOG_PKCS11 | TLOG_USER, LOG_ERR, "PIN too long for PIN entry");
		return 0;
	}
	strcpy (pin, cmd->cmd.pio_data.pioc_pinentry.pin);
	memset (cmd->cmd.pio_data.pioc_pinentry.pin,
			0,
			sizeof (cmd->cmd.pio_data.pioc_pinentry.pin));
	tlog (TLOG_PKCS11, LOG_DEBUG, "Returning entered PIN and OK from PIN entry");
	return 1;
}


void setup_pinentry (void) {
	;	/* Nothing to do */
}

void cleanup_pinentry (void) {
	;	/* Nothing to do */
}

