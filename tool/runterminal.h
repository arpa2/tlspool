#ifndef TLSPOOL_TOOL_RUNTERMINAL_H
#define TLSPOOL_TOOL_RUNTERMINAL_H

#include <tlspool/starttls.h>

/**
 * Runs a message loop on file-descriptor @p chanio.
 *
 * @param chanio file-descriptor for communications.
 * @param sigcont pointer to a boolean which indicates if SIGCONT has
 * 		been received; reset to false (0) on continue.
 * @param tlsdata pointer to data structure for starttls. This is
 * 		modified by the function when (re)starting a connection.
 * @param startflags int value (a bitwise-or of PIOF_STARTTLS_* values)
 * 		used in starting the TLS connection.
 * @param localid name of local id; if non-NULL, this is copied into @p tlsdata
 * @param remoteid name of remote; if non-NULL, copied into @p tlsdata
 */
void runterminal (int chanio, int *sigcont, starttls_t *tlsdata,
		  uint32_t startflags,
		  const char *localid, const char *remoteid
 		);

#endif
