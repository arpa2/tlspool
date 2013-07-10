/* tlspool/pinentry.c -- Connect to the local tlspool and enter PINs.
 */


#include <stdlib.h>
#include <stdio.h>

#include <errno.h>
#include <sys/socket.h>
#include <sys/un.h>


#include <tlspool.h>


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
	sox = socket (SOCK_STREAM, AF_UNIX, 0);
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
			pwd = NULL;
			bzero (pwd, strlen (pwd));
		}
		if (send (sox, &pio, sizeof (pio), 0) != sizeof (pio)) {
			perror ("Failed to send message to TLS pool");
			break;
		}
		if (recv (sox, &pio, sizeof (pio), 0) != sizeof (pio)) {
			perror ("Failed to read full message from TLS pool");
			break;
		}
		if (pio.pio_cmd != PIOC_PINENTRY_V1) {
			pio.pio_cmd = PIOC_ERROR_V1;
			pio.pio_data.pioc_error.tlserrno = EBADE;
			strcpy (pio.pio_data.pioc_error.message, "Unexpected response from TLS pool");
		}
		if (pio.pio_cmd == PIOC_ERROR_V1) {
			errno = pio.pio_data.pioc_error.tlserrno;
			perror (pio.pio_data.pioc_error.message);
			break;
		}
		fprintf (stdout, "Token Manuf: %s\n     Model:  %s\n      Serial: %s\n      Label: %s\n    Attempt: %d", pe->token_manuf, pe->token_model, pe->token_serial, pe->token_label, pe->attempt);
		pwd = getpass (pe->prompt);
	}
	bzero (&pio.pio_data, sizeof (pio.pio_data));
	close (sox);
	exit (0);
}

