/* onlinecheck.c -- Run checks from online.c
 *
 * This code runs outside of the TLS Pool and is not entangled with its
 * validation expressions or starttls.c procedures.  They do refer to a
 * few online resources that are assumed to be up and reachable.
 *
 * From: Rick van Rein <rick@openfortress.nl>
 */


#include <stdlib.h>

#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>
#include <fcntl.h>

#define tlog(...)

#include "../src/online.c"

uint8_t testcert [16384];
size_t testcert_size;


/* We don't care about the certificate at all; it is just a literal binblurb
 * stored in the right places in our test infrastructure.  Note that you may
 * run into failures if you are behind the latest sources; this may be the
 * case when we decide to look at the client name after all.
 */
void readcert (void) {
	int ok = 1;
	int fd = open ("tlspool-test-client-cert.der", O_RDONLY);
	ok = ok && (fd >= 0);
	if (ok) {
		testcert_size = read (fd, testcert, sizeof (testcert));
		ok = ok && (testcert_size > 0) && (testcert_size <= sizeof (testcert) - 1);
	}
	if (fd >= 0) {
		close (fd);
	}
	if (!ok) {
		fprintf (stderr, "Failed to read test certificate file\n");
		exit (1);
	}
}


void printoutput (char *tdesc, int tres) {
	printf ("Test:    %s\nreports: ", tdesc);
	switch (tres) {
	case ONLINE_SUCCESS:
		printf ("ONLINE_SUCCESS\n");
		break;
	case ONLINE_NOTFOUND:
		printf ("ONLINE_NOTFOUND\n");
		break;
	case ONLINE_INVALID:
		printf ("ONLINE_INVALID\n");
		break;
	default:
		printf ("SOMETHING SILLY\n");
		break;
	}
}


int main (int argc, char *argv []) {
	int exitval = 1;
	int output;
	setup_online ();
	readcert ();
	output = online_globaldir_x509 ("tester1@test.arpa2.org", testcert, testcert_size);
	printoutput ("tester1 under DNSSEC domain", output);
	output = online_globaldir_x509 ("tester2@test.arpa2.org", testcert, testcert_size);
	printoutput ("tester2 under DNSSEC domain", output);
	output = online_globaldir_x509 ("tester3@test.arpa2.org", testcert, testcert_size);
	printoutput ("tester3 under DNSSEC domain", output);
	output = online_globaldir_x509 ("tester1@insecure.test.arpa2.org", testcert, testcert_size);
	printoutput ("tester1 under insecure domain", output);
	output = online_globaldir_x509 ("tester2@insecure.test.arpa2.org", testcert, testcert_size);
	printoutput ("tester2 under insecure domain", output);
	output = online_globaldir_x509 ("tester3@insecure.test.arpa2.org", testcert, testcert_size);
	printoutput ("tester3 under insecure domain", output);
	cleanup_online ();
	exit (exitval);
}

