/* mbedTLS driver module for the TLS Pool
 *
 * When this module is configured as the STARTTLS driver, it will be
 * contacted for all STARTTLS operations, and for later queries that
 * reflect on it.
 *
 * From: Rick van Rein <rick@openfortress.nl>
 */


#include <stdint.h>
#include <stdbool.h>


#include <tlspool/commands.h>
#include <tlspool/internal.h>

#include <errno.h>
#include <com_err.h>
#include <errortable.h>


void setup_starttls (void) {
	;
}

void cleanup_starttls (void) {
	;
}


void starttls_pkcs11_provider (char *p11path) {
	;
}


void starttls (struct command *cmd) {
	send_error (cmd, E_TLSPOOL_INFO_NOT_FOUND, "STARTTLS not yet implemented for mbedTLS");
}

void starttls_prng (struct command *cmd) {
	send_error (cmd, E_TLSPOOL_INFO_NOT_FOUND, "STARTTLS not yet implemented for mbedTLS");
}

void starttls_info_cert_subject (struct command *cmd, struct ctlkeynode *node, uint16_t len, uint8_t *buf) {
	send_error (cmd, E_TLSPOOL_INFO_NOT_FOUND, "STARTTLS not yet implemented for mbedTLS");
}

void starttls_info_cert_issuer (struct command *cmd, struct ctlkeynode *node, uint16_t len, uint8_t *buf) {
	send_error (cmd, E_TLSPOOL_INFO_NOT_FOUND, "STARTTLS not yet implemented for mbedTLS");
}

void starttls_info_cert_subjectaltname (struct command *cmd, struct ctlkeynode *node, uint16_t len, uint8_t *buf) {
	send_error (cmd, E_TLSPOOL_INFO_NOT_FOUND, "STARTTLS not yet implemented for mbedTLS");
}

void starttls_info_chanbind_tls_unique (struct command *cmd, struct ctlkeynode *node, uint16_t len, uint8_t *buf) {
	send_error (cmd, E_TLSPOOL_INFO_NOT_FOUND, "STARTTLS not yet implemented for mbedTLS");
}

void starttls_info_chanbind_tls_server_end_point (struct command *cmd, struct ctlkeynode *node, uint16_t len, uint8_t *buf) {
	send_error (cmd, E_TLSPOOL_INFO_NOT_FOUND, "STARTTLS not yet implemented for mbedTLS");
}

