/* tlspool/pinentry.c -- Connect to the local tlspool and enter PINs. */


#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <pthread.h>

#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <gnutls/gnutls.h>

#include <tlspool/internal.h>


/*
 * The user facility for entering PINs.  This is a simple loop that
 * continually asks the TLS pool to send PIN inquiries, and then
 * presents them on the console to the end user.  Chances are that
 * most will see this as an arcane method due to its textual nature,
 * even though that makes its security much more controllable.
 *
 * There is no reason why GUI programs could not do similar things,
 * though.  To those, this function can serve as example code.
 */
void enter_pins (char *pinsocket) {
	struct sockaddr_un sun;
	int len = strlen (pinsocket);
	struct tlspool_command pio;
	struct pioc_pinentry *pe = &pio.pio_data.pioc_pinentry;
	char *pwd = NULL;
	int sox;

	/*
	 * Connect to the UNIX domain socket for PIN entry
	 */
	if (len + 1 > sizeof (sun.sun_path)) {
		fprintf (stderr, "Socket path too long: %s\n", pinsocket);
		exit (1);
	}
	strcpy (sun.sun_path, pinsocket);
	len += sizeof (sun.sun_family);
	sun.sun_family = AF_UNIX;
	sox = socket (AF_UNIX, SOCK_STREAM, 0);
	if (!sox) {
		perror ("Failed to allocate UNIX domain socket");
		exit (1);
	}
	if (connect (sox, (struct sockaddr *) &sun, len) == -1) {
		perror ("Failed to connect to PIN socket");
		exit (1);
	}
	
	/*
	 * Setup the command structure
	 */
	bzero (&pio.pio_data, sizeof (pio.pio_data));
	pio.pio_reqid = 666;

	/*
	 * Iteratively request what token needs a PIN, and provide it.
	 */
	while (1) {
		pio.pio_cmd = PIOC_PINENTRY_V1;
		bzero (pe->pin, sizeof (pe->pin));
		if (pwd) {
			if (strlen (pwd) + 1 > sizeof (pe->pin)) {
				fprintf (stderr, "No support for PIN lenghts over 128\n");
			} else {
				strcpy (pe->pin, pwd);
			}
			bzero (pwd, strlen (pwd));
		}
		fprintf (stderr, "DEBUG: Offering PIN service to TLS pool\n");
		if (send (sox, &pio, sizeof (pio), 0) != sizeof (pio)) {
			pio.pio_cmd = PIOC_ERROR_V1;
			pio.pio_data.pioc_error.tlserrno = errno;
			strcpy (pio.pio_data.pioc_error.message, "Failed to send message to TLS pool");
		} else {
			if (recv (sox, &pio, sizeof (pio), 0) != sizeof (pio)) {
				pio.pio_cmd = PIOC_ERROR_V1;
				pio.pio_data.pioc_error.tlserrno = errno;
				strcpy (pio.pio_data.pioc_error.message, "Failed to read full message from TLS pool");
			} else {
				if ((pio.pio_cmd != PIOC_PINENTRY_V1) && (pio.pio_cmd != PIOC_ERROR_V1)) {
					printf ("DEBUG: Received funny command 0x%08x instead of 0x%08x\n", pio.pio_cmd, PIOC_PINENTRY_V1);
					pio.pio_cmd = PIOC_ERROR_V1;
					pio.pio_data.pioc_error.tlserrno = EPROTO;
					strcpy (pio.pio_data.pioc_error.message, "Unexpected command response from TLS pool");
				}
			}
		}
		if (pio.pio_cmd == PIOC_ERROR_V1) {
			errno = pio.pio_data.pioc_error.tlserrno;
			perror (pio.pio_data.pioc_error.message);
			break;
		}
		fprintf (stderr, "DEBUG: Received PIN inquiry from TLS pool\n");
		fprintf (stdout, "Token Manuf: %s\n     Model:  %s\n      Serial: %s\n      Label: %s\n    Attempt: %d", pe->token_manuf, pe->token_model, pe->token_serial, pe->token_label, pe->attempt);
		pwd = getpass (pe->prompt);
	}
	bzero (&pio.pio_data, sizeof (pio.pio_data));
	close (sox);
	exit (1);
}


static pthread_mutex_t pinentry_lock = PTHREAD_MUTEX_INITIALIZER;
static struct command *pinentry_cmd = NULL;


/*
 * Register a application socket as one that is willing to process PIN entry
 * requests.  The file descriptor may also be used for other functions,
 * so it is only safe to use as a sending channel.  Registration is just
 * for one try, after which the application protocol will let it re-register.
 */
void register_pinentry_command (struct command *cmd) {
	int error = 0;
	pthread_mutex_lock (&pinentry_lock);
	if (!pinentry_cmd) {
		pinentry_cmd = cmd;
	} else {
		error = 1;
	}
	pthread_mutex_unlock (&pinentry_lock);
	if (error) {
		send_error (cmd, EBUSY, "Another PIN entry process is active");
		return;
	}
	send_error (cmd, ENOSYS, "PIN entry not implemented yet");
}


/*
 * Implement the GnuTLS function for PIN callback.  This function will
 * address the currently set PIN handler connection.
 */
int gnutls_pin_callback (void *userdata, int attempt, const char *token_url, const char *token_label, unsigned int flags, char *pin, size_t pin_max) {
	struct command *cmd;
	int appsox;
	int retval = 0;
	//TODO// First try to find the PIN locally
	pthread_mutex_lock (&pinentry_lock);
	cmd = pinentry_cmd;
	if (/*TODO(appsox != -1) &&*/ (cmd != NULL)) {
		//TODO// pinentry_appsox = -1;
		//TODO// cmd = NULL;
	} else {
		retval = GNUTLS_A_USER_CANCELED;
	}
	pthread_mutex_unlock (&pinentry_lock);
	if (retval) {
		return retval;
	}
	//TODO// Construct PIN ENTRY response, claim responses and send to the origin
	//TODO// Await response or timeout
}


