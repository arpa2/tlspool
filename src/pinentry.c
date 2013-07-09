/* tlspool/pinentry.c -- Connect to the local tlspool and enter PINs.
 */


#include <stdlib.h>
#include <sys/socket.h>


void enter_pins (char *pinsocket) {
	struct sockaddr_un sun;
	int len = strlen (pinsocket);
	struct tlspool_packet pio;

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
	 * Iteratively request what token needs a PIN, and provide it.
	 */
	do {
		char *pwd;
		pio.cmd = TLSPOOL_CMD_PIN_NEED;
		pio.pin_index = pinidx;
		//TODO// sox.send (pio);
		//TODO// sox.recv (pio);
		if (pio.cmd != TLSPOOL_CMD_TOKEN_PIN_REQUEST) {
			break;
		}
		fprintf (stdout, "PKCS #11 Manuf: %32s\nPKCS #11 Token: %32s\n", pio.pin_manuf, pio.pin_token);
		pwd = getpass ("PIN: ");
		pio.pin_len = strlen (pwd);
		if (pio.pin_len == 0) {
			break;
		}
		if (pio.pin_len > 128) {
			fprintf (stderr, "No support for PIN lenghts over 128\n");
			exit (1);
		}
		pio.cmd = TLSPOOL_CMD_TOKEN_PIN_SET;
		memcpy (pio.pin_value, pwd, pio.pin_len);
		//TODO// sox.send (pio);
		pio.pin_len = 0;
		bzero (pio.pin_value, sizeof (pio.pin_value));
		//TODO// sox.recv (pio);
		if (TODO:failed) {
			fprintf (stderr, "PIN wrong, %d attempts left.  Skipping this token.\n", pio.pin_attemptsleft);
			pinidx++;
		}
	} while (pio.cmd == TLSPOOL_CMD_TOKEN_PIN);
	close (sox);
	exit (0);
}

