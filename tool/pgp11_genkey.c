/* pgp11_genkey.c -- Build an OpenPGP public key from a PKCS #11 RSA private key
 *
 * Commandline arguments:
 *  - a library path for a PKCS #11 provider
 *  - a pkcs11: URI for a pre-existing RSA private key to use
 *  - a userid; normally of the form "User Name <box@mail.dom>"
 *  - an output file name (filled with the binary key form)
 *
 * The PIN will be needed; if it is not provided in environment variable
 * GNUTLS_PIN, then an interactive request will prompt for it.
 *
 * This program uses P11-KIT to load a provider, and to locate a pre-existing
 * private key from which it generates a PGP public key.
 *
 * From: Rick van Rein <rick@openfortress.nl>
 */


#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <time.h>

#include <ldap.h>
#include <pkcs11.h>
#include <openssl/sha.h>

#define P11_KIT_FUTURE_UNSTABLE_API
#include <p11-kit/p11-kit.h>
#include <p11-kit/uri.h>
#include <p11-kit/iter.h>


#ifndef CKC_OPENPGP
#define CKC_OPENPGP ((CK_CERTIFICATE_TYPE) (CKC_VENDOR_DEFINED|0x00504750))
#endif


#ifdef DEBUG_SIGNUPDATE
/* Debugging routine: Print the hexbytes that are fed into the C_SignUpdate
 * routines.
 */
CK_RV C_SignUpdateDebug (CK_SESSION_HANDLE hsm, CK_BYTE_PTR data, CK_ULONG dlen) {
	int i;
	fprintf (stderr, "DEBUG: Signature hexbytes:");
	for (i=0; i<dlen; i++) {
		fprintf (stderr, " %02x", data [i]);
	}
	fprintf (stderr, "\n");
	return C_SignUpdate (hsm, data, dlen);
}
#define C_SignUpdate C_SignUpdateDebug
#endif //DEBUG_SIGNUPDATE


static CK_FUNCTION_LIST *fun = NULL;



/* Append a UserID packet to the given buffer.  This appends bytes at
 * pos into buf, clipped at totlen, and returns the new position after
 * this packet.  The userid is used for the OpenPGP packet UserID.
 *
 * If buf is NULL, the actual writing is not done, but only the length
 * calculations.
 *
 * If sha256ctx is provided, it will be updated with the public key info
 * as used in various self-signature types.
 */
unsigned int add_userid_pkt (uint8_t *buf, unsigned int pos, char *userid, CK_SESSION_HANDLE hsm, SHA256_CTX *sha) {
	unsigned int txtlen = strlen (userid);
	unsigned int pktlen = txtlen;
	uint8_t hashtag [5];
	CK_RV ckr;
	if (!buf) {
		pktlen += (txtlen < 192)? 2: 3;
		return pos + pktlen;
	}
	hashtag [0] = 0xb4;
	hashtag [1] = 0;
	hashtag [2] = 0;
	hashtag [3] = txtlen >> 8;
	hashtag [4] = txtlen & 0xff;
	if ((ckr = fun->C_SignUpdate (hsm, hashtag, 5)) != CKR_OK) {
		fprintf (stderr, "%08x: Failed to append UserID hashtag to signature\n", ckr);
		exit (1);
	}
	if (sha) {
		SHA256_Update (sha, hashtag, 5);
	}
	buf [pos++] = 0xc0 | 13;
	if (txtlen < 192) {
		buf [pos++] = txtlen;
		pktlen += 2;
	} else {
		buf [pos++] = ((txtlen - 192) >>   8) + 192;
		buf [pos++] =  (txtlen - 192) & 0xff;
		pktlen += 3;
	}
	memcpy (buf + pos, userid, txtlen);
	pos += txtlen;
	if ((ckr = fun->C_SignUpdate (hsm, buf + pos - txtlen, txtlen)) != CKR_OK) {
		fprintf (stderr, "%08x: Failed to attach UserID text to signature\n", ckr);
		exit (1);
	}
	if (sha) {
		SHA256_Update (sha, buf + pos - txtlen, txtlen);
	}
	return pos;
}


/* Append an RSA public key packet to the given buffer.  This appends
 * bytes at pos into buf, clipped at totlen, and returns the new position
 * after this packet.  The format assumed is RSA, with the given modulus
 * and public key.
 *
 * If buf is NULL, the actual writing is not done, but only the length
 * calculations.
 *
 * If sha256ctx is provided, it will be updated with the public key info
 * as used in various self-signature types.
 *
 * While generating the public key packet, the fingerprint of the public
 * key will also be determined.
 */
unsigned int add_pubkey_rsa_pkt (uint8_t *buf, unsigned int pos, uint8_t *modulus, unsigned int modulus_len, uint8_t *pubexp, unsigned int pubexp_len, CK_SESSION_HANDLE hsm, SHA256_CTX *sha, uint8_t fingerprint [20], int subkey) {
	unsigned int keylen = 6 + 2 + modulus_len + 2 + pubexp_len;
	time_t now;
	uint8_t hashtag [3];
	uint8_t mask;
	CK_RV ckr;
	SHA_CTX fpr;
	if (!buf) {
		keylen += (keylen >= 192)? 3: 2;
		return pos + keylen;
	}
	SHA1_Init (&fpr);
	buf [pos++] = 0xc0 | (subkey? 14: 6);
	if (keylen < 192) {
		buf [pos++] = keylen;
	} else {
		buf [pos++] = ((keylen - 192) >> 8  ) + 192;
		buf [pos++] =  (keylen - 192) & 0xff;
	}
	hashtag [0] = 0x99;
	hashtag [1] = keylen >> 8;
	hashtag [2] = keylen & 0xff;
	if ((ckr = fun->C_SignUpdate (hsm, hashtag, 3)) != CKR_OK) {
		fprintf (stderr, "%08x: Failed to append public key hashtag to signature\n", ckr);
		exit (1);
	}
	if (sha) {
		SHA256_Update (sha, hashtag, 3);
	}
	SHA1_Update (&fpr, hashtag, 3);
	buf [pos++] = 4;
	time (&now);	//TODO// Share priv-starttime & fpr with all pubkeys?
	buf [pos++] = (now >> 24) & 0xff;
	buf [pos++] = (now >> 16) & 0xff;
	buf [pos++] = (now >>  8) & 0xff;
	buf [pos++] = (now      ) & 0xff;
	buf [pos++] = 1;	/* RSA */
	buf [pos++] = (modulus_len * 8) >> 8;
	buf [pos++] = (modulus_len * 8) & 0xff;
	mask = 0x80;
	while (mask && ((*modulus & mask) == 0x00)) {
		buf [pos-1]--;
		if (buf [pos-1] == 0xff) {
			buf [pos-2]--;
		}
		mask >>= 1;
		fprintf (stderr, "Reducing modulus MPI length by 1 bit because first byte is 0x%02x\n", *modulus);
	}
	memcpy (buf + pos, modulus, modulus_len);
	pos += modulus_len;
	buf [pos++] = (pubexp_len * 8) >> 8;
	buf [pos++] = (pubexp_len * 8) & 0xff;
	mask = 0x80;
	while (mask && ((*pubexp & mask) == 0x00)) {
		buf [pos-1]--;
		if (buf [pos-1] == 0xff) {
			buf [pos-2]--;
		}
		mask >>= 1;
		fprintf (stderr, "Reducing pubexp MPI length by 1 bit because first byte is 0x%02x\n", *pubexp);
	}
	memcpy (buf + pos, pubexp,  pubexp_len );
	pos += pubexp_len;
	if ((ckr = fun->C_SignUpdate (hsm, buf + pos - keylen, keylen)) != CKR_OK) {
		fprintf (stderr, "%08x: Failed to append public key data to signatures\n", ckr);
		exit (1);
	}
	if (sha) {
		SHA256_Update (sha, buf + pos - keylen, keylen);
	}
	SHA1_Update (&fpr, buf + pos - keylen, keylen);
	SHA1_Final (fingerprint, &fpr);
	printf ("DEBUG: Fingerprint is %02X%02X %02X%02X %02X%02X %02X%02X %02X%02X  %02X%02X %02X%02X %02X%02X %02X%02X %02X%02X\n", fingerprint [0], fingerprint [1], fingerprint [2], fingerprint [3], fingerprint [4], fingerprint [5], fingerprint [6], fingerprint [7], fingerprint [8], fingerprint [9], fingerprint [10], fingerprint [11], fingerprint [12], fingerprint [13], fingerprint [14], fingerprint [15], fingerprint [16], fingerprint [17], fingerprint [18], fingerprint [19]);
	return pos;
}


/* Append a sha256rsa signature with the given packet tag.  The signature
 * and its length in bytes are provided.
 * 
 * If buf is NULL, only the length calculations are performed.
 *
 * The HSM context is assumed to have collected the bytes that need to
 * be taken into account before the signature packet data and the trailer.
 */
unsigned int add_signature_sha256rsa_pkt (uint8_t *buf, unsigned int pos, int sigtype, CK_SESSION_HANDLE hsm, SHA256_CTX *sha, uint8_t fingerprint [20]) {
	CK_ULONG p11siglen = (2048 + 7) / 8;
	CK_RV ckr;
	unsigned int siglen = 31 + p11siglen;
	uint8_t hash [SHA256_DIGEST_LENGTH];
	time_t now;
	uint8_t mask;
	uint8_t hashtrail [6];
	unsigned int startpos;
	if (!buf) {
		siglen += (siglen < 192)? 2: 3;
		return pos + siglen;
	}
	buf [pos++] = 0xc0 | 2;
	if (siglen < 192) {
		buf [pos++] = siglen;
	} else {
		buf [pos++] = ((siglen - 192) >> 8  ) + 192;
		buf [pos++] =  (siglen - 192) & 0xff;
	}
	startpos = pos;
	buf [pos++] = 4;
	buf [pos++] = sigtype;
	buf [pos++] = 1;	/* RSA */
	buf [pos++] = 8;	/* SHA256 */
	buf [pos++] = 0;	/* Hashed subpackets length */
	buf [pos++] = 9;
	buf [pos++] = 5;	/* Hashed subpacket: Time */
	buf [pos++] = 2;
	time (&now);
	buf [pos++] = (now >> 24) & 0xff;
	buf [pos++] = (now >> 16) & 0xff;
	buf [pos++] = (now >>  8) & 0xff;
	buf [pos++] = (now      ) & 0xff;
	buf [pos++] = 2;	/* Hashed subpacket: Key flags */
	buf [pos++] = 27;
	buf [pos++] = (sigtype == 0x18)? 0x0c: 0x23;	/* With signing 0x02 */
	if ((ckr = fun->C_SignUpdate (hsm, buf + startpos, pos - startpos)) != CKR_OK) {
		fprintf (stderr, "%08x: Failed to append signed subpackets to signature\n", ckr);
		exit (1);
	}
	SHA256_Update (sha, buf + startpos, pos - startpos);
	hashtrail [0] = 4;
	hashtrail [1] = 0xff;
	hashtrail [2] = 0;
	hashtrail [3] = 0;
	hashtrail [4] = 0;
	hashtrail [5] = pos - startpos;
	if ((ckr = fun->C_SignUpdate (hsm, hashtrail, 6)) != CKR_OK) {
		fprintf (stderr, "%08x: Failed to append signature trailer to signature\n", ckr);
		exit (1);
	}
	SHA256_Update (sha, hashtrail, 6);
	SHA256_Final (hash, sha);
	buf [pos++] = 0;	/* Length of unhashed subpackets */
	buf [pos++] = 10;
	buf [pos++] = 9;	/* Unhashed subpacket: Issuer keyID */
	buf [pos++] = 16;
	memcpy (buf + pos, fingerprint + 20 - 8, 8);
	pos += 8;
	buf [pos++] = hash [0];
	buf [pos++] = hash [1];
	buf [pos++] = (p11siglen * 8) >> 8;
	buf [pos++] = (p11siglen * 8) & 0xff;
	printf ("DEBUG: signature packet after header is %d\n", pos - startpos);
	printf ("DEBUG: p11siglen  pre-sign is %d\n", p11siglen);
	if ((ckr = fun->C_SignFinal (hsm, buf + pos, &p11siglen)) != CKR_OK) {
		fprintf (stderr, "%08x: Failed to retrieve signature\n", ckr);
		exit (1);
	}
	printf ("DEBUG: p11siglen post-sign is %d\n", p11siglen);
	printf ("DEBUG: p11sig is %02x %02x...%02x %02x\n", buf [pos], buf [pos+1], buf [pos+p11siglen-2], buf [pos+p11siglen-1]);
	mask = 0x80;
	while (mask && ((buf [pos] & mask) == 0x00)) {
		buf [pos-1]--;
		if (buf [pos-1] == 0xff) {
			buf [pos-2]--;
		}
		mask >>= 1;
		fprintf (stderr, "Reducing signature MPI length by 1 bit because first byte is 0x%02x\n", buf [pos]);
	}
	//TODO// Does this call ever modify p11siglen?  Strip leading 0 bytes?
	pos += p11siglen;
	return pos;
}


/* Construct a packet holding the OpenPGP key packet, with a single UserID
 * packet and the appropriate self-signatures.  There are no signatures by
 * others on this key.
 *
 * The data is written to buf, which can hold the entire structure, and
 * the length filled is returned.  If buf is NULL, only the size is
 * calculated and returned; cryptographic calculations are then bypassed.
 *
 * The name may be NULL, in which case it will be omitted from the UserID.
 * The email may not be NULL.
 */
unsigned int construct_pubkey_rsa_packet (uint8_t *buf, uint8_t fpr [20], uint8_t *modulus, unsigned int modulus_len, uint8_t *pubexp, unsigned int pubexp_len, char *userid, CK_SESSION_HANDLE hsm, CK_OBJECT_HANDLE privkey) {
	unsigned int pos = 0;
	CK_MECHANISM sigmech = { CKM_SHA256_RSA_PKCS, NULL_PTR, 0 };
	CK_RV ckr;
	SHA256_CTX sha, keysha;
	if (buf) {
		if ((ckr = fun->C_SignInit (hsm, &sigmech, privkey)) != CKR_OK) {
			fprintf (stderr, "%08x: Failed to initiate UserID signing on %d\n", ckr, privkey);
			exit (1);
		}
		SHA256_Init (&sha);
	}
	printf ("DEBUG: add_pubkey_rsa_pkt at %d\n", pos);
	pos = add_pubkey_rsa_pkt (buf, pos, modulus, modulus_len, pubexp, pubexp_len, hsm, buf? &sha: NULL, fpr, 0);
	if (buf) {
		memcpy (&keysha, &sha, sizeof (keysha));
	}
	//NOT_REQUIRED// pos = add_signature_sha256rsa_pkt (buf, pos, 0x19, selfsig_hash, selfsig, selfsig_len);
	printf ("DEBUG: add_userid_pkt at %d\n", pos);
	pos = add_userid_pkt (buf, pos, userid, hsm, buf? &sha: NULL);
	printf ("DEBUG: add_signature_sha256rsa_pkt at %d\n", pos);
	pos = add_signature_sha256rsa_pkt (buf, pos, 0x10, hsm, buf? &sha: NULL, fpr);
	printf ("DEBUG: add_pubkey_rsa_pkt at %d\n", pos);
	if (buf) {
		if ((ckr = fun->C_SignInit (hsm, &sigmech, privkey)) != CKR_OK) {
			fprintf (stderr, "%08x: Failed to initiate UserID signing on %d\n", ckr, privkey);
			exit (1);
		}
		SHA256_Init (&sha);
	}
	/*void*/ add_pubkey_rsa_pkt (buf, pos, modulus, modulus_len, pubexp, pubexp_len, hsm, buf? &sha: NULL, fpr, 0);
	printf ("DEBUG: add_pubkey_rsa_pkt at %d\n", pos);
	pos = add_pubkey_rsa_pkt (buf, pos, modulus, modulus_len, pubexp, pubexp_len, hsm, buf? &keysha: NULL, fpr, 1);
	printf ("DEBUG: add_signature_sha256rsa_pkt at %d\n", pos);
	pos = add_signature_sha256rsa_pkt (buf, pos, 0x18, hsm, buf? &keysha: NULL, fpr);
	printf ("DEBUG: file ends at %d\n", pos);
	return pos;
}


/* Allocate and fill an OpenPGP signature "file", holding the PGP public
 * key info and a userID containing the email address and optional name.
 * 
 * The "file" is returned in file, its length in file_len.
 *
 * The structure returned must be freed with free() when done.
 */
void pubkey_file (uint8_t **file, unsigned int *file_len, uint8_t fingerprint [20], char *userid, CK_SESSION_HANDLE hsm, CK_OBJECT_HANDLE privkey) {
	unsigned int flen2;
	CK_KEY_TYPE keytype;
	CK_BYTE modulus [(2048+7)/8];
	CK_BYTE pubexp [3];
	CK_RV ckr;
	CK_ATTRIBUTE template [] = {
		{ CKA_KEY_TYPE,        &keytype, sizeof (keytype) },
		{ CKA_MODULUS,         &modulus, sizeof (modulus) },
		{ CKA_PUBLIC_EXPONENT, &pubexp,  sizeof (pubexp ) }
	};
	if ((ckr = fun->C_GetAttributeValue (hsm, privkey, template, 3)) != CKR_OK) {
		fprintf (stderr, "%08x: Failed to obtain public key attributes for private key %d\n", ckr, privkey);
		exit (1);
	}
	if (template [0].ulValueLen != sizeof (keytype)) {
		fprintf (stderr, "Key type of funny size: %d not %d\n", template [0].ulValueLen, sizeof (keytype));
		exit (1);
	}
	if (template [1].ulValueLen != sizeof (modulus)) {
		fprintf (stderr, "Modulus of funny size: %d not %d\n", template [1].ulValueLen, sizeof (modulus));
		exit (1);
	}
	if (template [2].ulValueLen != sizeof (pubexp )) {
		fprintf (stderr, "Public exponent of funny size: %d not %d\n", template [2].ulValueLen, sizeof (pubexp ));
		exit (1);
	}
	if (keytype != CKK_RSA) {
		fprintf (stderr, "The private key is not an RSA key, which this program assumes\n");
		exit (1);
	}
	*file_len = construct_pubkey_rsa_packet (NULL, fingerprint, modulus, sizeof (modulus), pubexp, sizeof (pubexp), userid, hsm, privkey);
	if (*file_len > 4096) {
		fprintf (stderr, "Unbelievably long PGP public key file length\n");
		exit (1);
	}
	*file = malloc (*file_len);
	if (*file == NULL) {
		fprintf (stderr, "Out of memory allocating public key file structure\n");
		exit (1);
	}
	flen2 = construct_pubkey_rsa_packet (*file, fingerprint, modulus, sizeof (modulus), pubexp, sizeof (pubexp), userid, hsm, privkey);
	if (*file_len != flen2) {
		fprintf (stderr, "Inconsistent public key file sizes in 1st and 2nd pass: %d became %d\n", *file_len, flen2);
		exit (1);
	}
}


int main (int argc, char *argv []) {

	//
	// Variable declarations
	//
	CK_RV ckr;
	CK_ULONG numslots;
	CK_SLOT_ID_PTR slots = NULL;
	int slotctr;
	CK_SLOT_ID matching_slot;
	CK_TOKEN_INFO tokeninfo;
	CK_UTF8CHAR tokenlabel [32];
	int found;
	CK_SESSION_HANDLE session;
	char *pin;
	uint8_t *file = NULL;
	unsigned int file_len = 0;
	P11KitUri *p11kituri = NULL;
	P11KitIter *p11kititer = NULL;
	CK_FUNCTION_LIST_PTR p11kititerfun [2];
	char *p11lib = NULL;
	char *p11obj = NULL;
	char *userid = NULL;
	char *outfnm = NULL;

	//
	// PKCS #11 communication variables
	//
	CK_OBJECT_HANDLE privkey = CK_INVALID_HANDLE;
	CK_BYTE fingerprint [20];

	//
	// Commandline processing
	//
	if (argc != 5) {
		fprintf (stderr,
"Usage: %s provider privkey userid outfile.pgp\n"
" - provider    is a path to a PKCS #11 service library\n"
" - privkey     is a PKCS #11 private key URI from that provider [RFC7512]\n"
" - userid      is a (quoted) PGP UserID like 'User Name <user@email.dom>'\n"
" - outfile.pgp is a filename for storage of the (binary) PGP public key\n",
				argv [0]);
		exit (1);
	}
	p11lib = argv [1];
	p11obj = argv [2];
	userid = argv [3];
	outfnm = argv [4];

	//
	// Parse the pkcs11: URI with p11-kit
	p11kituri = p11_kit_uri_new ();
	if (p11kituri == NULL) {
		fprintf (stderr, "Failed to allocate p11-kit URI\n");
		exit (1);
	}
	if (p11_kit_uri_parse (
			p11obj,
			P11_KIT_URI_FOR_OBJECT_ON_TOKEN,
			p11kituri) != P11_KIT_URI_OK) {
		fprintf (stderr, "Syntax error in pkcs11: URI\n");
		exit (1);
	}

	//
	// Gain access to PKCS #11
	//
	fun = p11_kit_module_load (p11lib, 0);
	if (fun == NULL) {
		fprintf (stderr, "%08x: Failed to load and initialise PKCS #11 provider library\n", ckr);
		exit (1);
	}
	if ((ckr = fun->C_Initialize (NULL_PTR)) != CKR_OK) {
		fprintf (stderr, "%08x: Failed to initialise PKCS #11 library\n");
	}
	if ((ckr = fun->C_GetSlotList (CK_TRUE, NULL_PTR, &numslots)) != CKR_OK) {
		fprintf (stderr, "%08x: Failed to find the number of PKCS #11 slots\n", ckr);
		exit (1);
	}
	if (numslots == 0) {
		fprintf (stderr, "There are no PKCS #11 slots available\n");
		exit (1);
	}
	if ((slots = calloc (sizeof (CK_SLOT_ID), numslots)) == NULL) {
		fprintf (stderr, "Failed to allocate room for %d PKCS #11 slots\n", numslots);
		exit (1);
	}
	if ((ckr = fun->C_GetSlotList (CK_TRUE, slots, &numslots)) != CKR_OK) {
		fprintf (stderr, "%08x: Failed to find the identities of %d PKCS #11 slots\n", ckr);
		exit (1);
	}
	found = 0;
	for (slotctr=0; slotctr<numslots; slotctr++) {
		if ((ckr = fun->C_GetTokenInfo (slots [slotctr], &tokeninfo)) != CKR_OK) {
			fprintf (stderr, "%08x: Failed to obtain information on token %d of %d\n", ckr, slotctr, numslots);
			exit (1);
		}
		if (p11_kit_uri_match_token_info (p11kituri, &tokeninfo)) {
			found++;
			matching_slot = slots [slotctr];
		}
	}
	if (found == 0) {
		fprintf (stderr, "Failed to find token matching the pkcs11: URI\n");
		exit (1);
	} else if (found > 1) {
		fprintf (stderr, "Found multiple tokens that match the pkcs11: URI -- I can't choose...\n");
		exit (1);
	}
	if ((ckr = fun->C_OpenSession (matching_slot, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &session)) != CKR_OK) {
		fprintf (stderr, "%08x: Failed to open PKCS #11 write session\n", ckr);
		exit (1);
	}
	pin = getenv ("GNUTLS_PIN");
	if ((!pin) || (!*pin)) {
		pin = getpass ("Token PIN: ");
	}
	if ((!pin) || (!*pin)) {
		fprintf (stderr, "Bailing out in lieu of PIN\n");
		exit (1);
	}
	if ((ckr = fun->C_Login (session, CKU_USER, pin, strlen (pin))) != CKR_OK) {
		fprintf (stderr, "%08x: Failed to login to PKCS #11 session\n", ckr);
		exit (1);
	}

	//
	// Locate the private key object from its pkcs11: URI
	p11kititer = p11_kit_iter_new (p11kituri, 0);
	if (p11kititer == NULL) {
		fprintf (stderr, "Failed to allocate p11-kit URI iterator\n");
		exit (1);
	}
	p11kititerfun [0] = fun;
	p11kititerfun [1] = NULL;
	p11_kit_iter_begin (p11kititer, p11kititerfun);
	if (p11_kit_iter_next (p11kititer) != CKR_OK) {
		fprintf (stderr, "Failed to iterate to private keys with the pkcs11: URI\n");
		exit (1);
	}
	privkey = p11_kit_iter_get_object (p11kititer);
	if (privkey == CK_INVALID_HANDLE) {
		fprintf (stderr, "Failed to find the private key with the pkcs11: URI\n");
		exit (1);
	}
	if (p11_kit_iter_next (p11kititer) != CKR_CANCEL) {
		fprintf (stderr, "The pkcs11: URI matches multiple private keys, can't choose...\n");
		exit (1);
	}

	//
	// Construct an OpenPGP public key "file" with one signed UserID
	//
	pubkey_file (&file, &file_len, fingerprint, userid, session, privkey);
	FILE *fh = fopen (outfnm, "w");
	if (fh == NULL) {
		fprintf (stderr, "Failed to open output file \"%s\"\n", outfnm);
		exit (1);
	}
	if (fwrite (file, 1, file_len, fh) != file_len) {
		fprintf (stderr, "Writing binary output to \"%s\" was incomplete\n", outfnm);
		exit (1);
	}
	fclose (fh);
	printf ("Constructed PGP public key and wrote its %d bytes to \"%s\"\n", file_len, outfnm);

	//
	// Cleanup and teardown
	//
	if (file != NULL) {
		free (file);
		file = NULL;
	}
	if (slots != NULL) {
		free (slots);
		slots = NULL;
	}
	if (p11kititer != NULL) {
		p11_kit_iter_free (p11kititer);
		p11kititer = NULL;
	}
	if (p11kituri != NULL) {
		p11_kit_uri_free (p11kituri);
		p11kituri = NULL;
	}
	if (		(fun->C_Logout (session) != CKR_OK) ||
			(fun->C_CloseSession (session) != CKR_OK) ||
			(fun->C_Finalize (NULL_PTR) != CKR_OK) ) {
		fprintf (stderr, "Failed to properly cleanup PKCS #11\n");
		p11_kit_module_release (fun);
		exit (1);
	}
	if (fun) {
		p11_kit_module_release (fun);
		fun = NULL;
	}
	return 0;
}
