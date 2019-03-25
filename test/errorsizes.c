/* Ensure that the current compiler regime is happy with error sizes.
 * See <tlspool/commands.h> above PIOC_ERROR_V2 for backgrounds.
 * We move error codes back and forth between pioc_error.tlserrno and
 * errno, where the former is an integer limited to int32_t values and
 * the latter has wild implementations but usually holds a small range
 * but is nonetheless the replacement for an "extern int errno" practice.
 *
 * From: Rick van Rein <rick@openfortress.nl>
 */


#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>

#include <errno.h>
#include <tlspool/commands.h>


#define NUM_VALS 18

long req_okay_vals [NUM_VALS] = {
	(long) (int32_t) 0x80000000,
	(long) (int32_t) 0x80000001,
	(long) (int32_t) 0x80100000,
	(long) (int32_t) 0xc0000000,
	(long) (int32_t) 0xf0000000,
	(long) (int32_t) 0xff000000,
	(long) (int32_t) 0xffffff00,
	(long) (int32_t) 0xffffffff,
	(long) (int32_t) 0x00000000,
	(long) (int32_t) 0x00000001,
	(long) (int32_t) 0x00000100,
	(long) (int32_t) 0x10000000,
	(long) (int32_t) 0x10000001,
	(long) (int32_t) 0x7f000000,
	(long) (int32_t) 0x7fffff00,
	(long) (int32_t) 0x7fffff01,
	(long) (int32_t) 0x7ffffff0,
	(long) (int32_t) 0x7fffffff
};


int main (int argc, char *argv []) {
	struct pioc_error pe1, pe2;
	int i;
	long out1, out2;
	int exit_val = 0;
	for (i=0; i<NUM_VALS; i++) {
		//
		// in.long -> tlserrno -> errno -> out.long
		pe1.tlserrno = req_okay_vals [i];
		errno = pe1.tlserrno;
		out1 = errno;
		if (out1 != req_okay_vals [i]) {
			fprintf (stderr, "FAILURE.  in %ld -> tlserrno %d -> errno %d -> out %ld\n",
						req_okay_vals [i],
						pe1.tlserrno,
						errno,
						out1);
			exit_val = 1;
		}
		//
		// in.long -> errno -> tlserrno -> out.long
		errno = req_okay_vals [i];
		pe2.tlserrno = errno;
		out2 = pe2.tlserrno;
		if (out2 != req_okay_vals [i]) {
			fprintf (stderr, "FAILURE.  in %ld -> errno %d -> tlserrno %d -> out %ld\n",
						req_okay_vals [i],
						errno,
						pe2.tlserrno,
						out2);
			exit_val = 1;
		}
	}
	exit (exit_val);
}
