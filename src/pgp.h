
#include <stdint.h>
#include <stdbool.h>


/* The PGP header structure walks through PGP data.
 */
typedef struct {
	uint8_t *ptr;
	uint32_t ofs;
	uint32_t len;
	uint32_t r64ofs;	// Set to PGP64_NA for binary data
} pgpcursor_st, *pgpcursor_t;

#define PGP64_NA (~(uint32_t) 0)


/* Setup a cursor on binary PGP data; always returns success. */
bool pgp_initcursor_binary (pgpcursor_t crs, uint8_t *data, uint32_t len);

/* Setup a cursor on radix64 PGP data; return success. */
bool pgp_initcursor_radix64 (pgpcursor_t crs, char *data, uint32_t len);

/* Fetch a byte from a pgpcursor; this may look either into binary data,
 * or into radix64-encoded data.  In the latter case, r64ofs is set to a
 * value different from PGP64_NA and indicates an additional byte offset.
 * In both cases, ptr points to the start of a fragment, and ofs and len
 * deal with the binary number of bytes.
 * This function returns 1 on success, 0 on failure.
 */
bool pgp_getbyte (pgpcursor_t crs, uint8_t *output);

/* Parse a PGP header pointed to by a given cursor.  Deliver a tag and an
 * inner PGP cursor, while advancing the original PGP cursor beyond the
 * tag.  The function returns a success value or zero for failure.
 * When sub is provided as NULL, it will not be entered.
 */
bool pgp_enter (pgpcursor_t seq, uint8_t *tag, pgpcursor_t sub);

