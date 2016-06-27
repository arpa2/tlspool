

#include <string.h>

#include "pgp.h"


static const char *radix64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";


/* Setup a cursor on binary PGP data; always returns success. */
bool pgp_initcursor_binary (pgpcursor_t crs, uint8_t *data, uint32_t len) {
	crs->ptr = data;
	crs->ofs = 0;
	crs->end = len;
	crs->r64ofs = PGP64_NA;
	return 1;
}

/* Setup a cursor on radix64 PGP data; return success. */
bool pgp_initcursor_radix64 (pgpcursor_t crs, char *data, uint32_t len) {
	bool end, cr, lf;
	uint32_t r64ofs;
	uint32_t r64len;
	// Ensure proper armour header line
	if (memcmp (data, "-----BEGIN PGP ", 15) != 0) {
		return 0;
	}
	// Skip over headers, searching for an empty line
	end = cr = lf = 0;
	r64ofs = 0;
	while (r64ofs < len) {
		if (data [r64ofs] == '\r') {
			end = end || cr;
			cr = 1;
		} else if (data [r64ofs] == '\n') {
			end = end || lf;
			lf = 1;
		} else {
			cr = 0;
			lf = 0;
			if (end) {
				// Come after the header lines
				break;
			}
		}
		r64ofs++;
	}
	if (!end) {
		return 0;
	}
	// Setup initial data
	crs->ptr = data;
	crs->ofs = 0;
	crs->r64ofs = r64ofs;
	// Count the characters of radix64; look for '-' and '=' endings
	// An ending '-' signals we didn't find an '=' and so counted the CRC24
	r64len = 0;
	while (1) {
		// Test if we outran the provided text block
		if (r64ofs + r64len >= len) {
			// Incomplete text form, return failure
			return 0;
		}
		// Test if the current character is a base64 character
		if (strchr (radix64, data [r64ofs + r64len]) != NULL) {
			r64len++;
			continue;
		}
		// Test if we hit upon the end of the radix64 body
		if (data [r64ofs + r64len] == '=') {
			// This must be the end of radix64 data
			if ((r64ofs + 1 < len) && (data [r64ofs + r64len + 1] == '=')) {
				// Two '=' pads, so 8 bit data in 2 r64 digits
				crs->end = 3 * (r64len - 2) / 4 + 1;
				break;
			} else {
				// One '=' pad, so 16 bit data in 3 r64 digits
				crs->end = 3 * (r64len - 3) / 4 + 2;
				break;
			}
		}
		// Test if we hit upon the trailer "-----END PGP...-----"
		if (data [r64ofs + r64len] == '-') {
			// No '=' pads, so we must've counted in the CRC-24
			crs->end = 3 * r64len / 4 - 3;
			break;
		}
		// Ignore unknown characters, usually whitespace
		r64ofs++;
	}
	return 1;
}


/* Fetch a byte from a pgpcursor; this may look either into binary data,
 * or into radix64-encoded data.  In the latter case, r64ofs is set to a
 * value different from PGP64_NA and indicates an additional byte offset.
 * In both cases, ptr points to the start of a fragment, and ofs and end
 * deal with the binary number of bytes.
 * This function returns 1 on success, 0 on failure.
 */
bool pgp_getbyte (pgpcursor_t crs, uint8_t *output) {
	int tmpofs;
	static const int8_t b64shifts [3] [3] = {
		{ 2, -4, 100 },
		{ 4, -2, 100 },
		{ 6,  0, 100 }
	};
	const int8_t *shifts;
	char c;
	uint8_t d;
	if (crs->ofs >= crs->end) {
		// The byte sequence has ended
		return 0;
	}
	if (crs->r64ofs == PGP64_NA) {
		// Read from binary input
		*output = crs->ptr [crs->ofs++];
	} else {
		// Read from radix64-input
		tmpofs = (crs->ofs * 4) / 3;
		shifts = b64shifts [crs->ofs % 3];
		crs->ofs++;
		*output = 0;
		while (*shifts != 100) {
			do {
				c = crs->ptr [crs->r64ofs + tmpofs];
				for (d=0; d<64; d++) {
					if (c == radix64 [d]) {
						break;
					}
				}
				if (d >= 64) {
					// Code point not found, so ignore
					crs->r64ofs++;
					continue;
				}
				if (*shifts >= 0) {
					d <<=   *shifts++;
				} else {
					d >>= - *shifts++;
				}
				*output |= d;
				tmpofs++;
			} while (0);
		}
	}
	return 1;
}


/* Parse a PGP header pointed to by a given cursor.  Deliver a tag and an
 * inner PGP cursor, while advancing the original PGP cursor beyond the
 * tag.  The function returns a success value or zero for failure.
 * When sub is provided as NULL, it will not be entered.
 */
bool pgp_enter (pgpcursor_t seq, uint8_t *tag, pgpcursor_t sub) {
	uint8_t here;
	uint8_t hdrlen;
	uint32_t intlen = 0;
	if (!pgp_getbyte (seq, &here)) {
		// Failed to read tag byte -- possibly the end of a seq
		return 0;
	}
	if ((here & 0x80) != 0x80) {
		// Not a proper tag
		return 0;
	}
	if ((here & 0xc0) == 0x80) {
		// Old format header
		*tag = (here & 0x3c) >> 2;
		if ((here & 0x03) == 0x03) {
			// Reject indefinate length packets
			return 0;
		}
		hdrlen = 1 + (1 << (here & 0x03));
		int i = 1;
		intlen = 0;
		while (i++ < hdrlen) {
			if (!pgp_getbyte (seq, &here)) {
				// Failed to read length byte
				return 0;
			}
			intlen <<= 8;
			intlen |= here;
		}
	} else {
		// Continue parsing new-style packet header
		hdrlen = 2;
		*tag = (here & 0x3f);
		if (!pgp_getbyte (seq, &here)) {
			// Failed to read lenght byte
			return 0;
		}
		if (here < 192) {
			intlen = here;
		} else if (here < 224) {
			hdrlen = 3;
			intlen = (here - 192) << 8;
			if (!pgp_getbyte (seq, &here)) {
				return 0;
			}
			intlen += here + 192;
		} else if (here == 255) {
			while (hdrlen++ < 6) {
				if (!pgp_getbyte (seq, &here)) {
					// Missing length byte
					return 0;
				}
				intlen <<= 8;
				intlen += here;
			}
		} else {
			// Illegal length format
			return 0;
		}
	}
	if (seq->ofs + intlen > seq->end) {
		// Inner structure appears longer than parseable length
		return 0;
	}
	// Update the inner pointer to point after the header, and inside it
	if (sub != NULL) {
		sub->ptr = seq->ptr;
		sub->ofs = seq->ofs;
		sub->end = seq->ofs + intlen;
		sub->r64ofs = seq->r64ofs;
	}
	// Update the seq to point after the current entry
	// Note how this code properly skips over radix64 whitespace
	while (intlen-- > 0) {
		pgp_getbyte (seq, &here);
	}
	return 1;
}

//TODO// Extract self-signature + check it
