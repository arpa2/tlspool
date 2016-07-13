/* Generic declarations of libtlspool for swig
 *
 * We use swig to generate wrappers for Python.
 *
 * We also include the generated result in the Git repository for TLS Pool,
 * so there is no requirement to install Swig unless you run "make veryclean"
 * instead of the usual "make clean".
 *
 * From: Rick van Rein <rick@openfortress.nl>
 */


%{

#include <tlspool/starttls.h>
#include <tlspool/commands.h>

%}


// by default, export nothing (we rename most anyway)

//LATER// %ignore "";


// welcome flags and tags

%rename("%(strip:[TLSPOOL_])s") "";
%rename("%s", regexpmatch$name="^PIOC_") "";
%rename("%s", regexpmatch$name="^PIOF_") "";


// basic data types

%inline{

	typedef char identity_t [128];

	typedef unsigned char ctlkey_t [16];

	typedef char service_t [16];

	typedef int pool_handle_t;

	typedef struct {
		char YYYYMMDD_producer [134];
		int facilities;
	} ping_data;

	typedef struct {
		int flags;
		int local;
		int ipproto;
		int streamid;
		identity_t localid;
		identity_t remoteid;
		ctlkey_t ctlkey;
		service_t service;
		int timeout;
	} starttls_data;

	typedef struct {
		int flags;
		ctlkey_t ctlkey;
		identity_t name;
	} control_data;

	typedef struct {
		int in1_len, in2_len, prng_len;
		char buffer [350];
	} prng_data;

};


// libtlspool.so

int tlspool_pid (char *opt_pidfile);

pool_handle_t tlspool_open_poolhandle (char *path);

int tlspool_ping (pingpool_t *pingdata);

int tlspool_starttls (int cryptfd, starttls_t *tlsdata,
                        int *privdata,
                        // int (*namedconnect) (starttls_t *tlsdata,void *privdata));
			void *swig_null_callback);

int tlspool_control_detach (ctlkey_t ctlkey);

int tlspool_control_reattach (ctlkey_t ctlkey);

int tlspool_prng (char *label, char *opt_ctxvalue,
                uint16_t prng_len, uint8_t *prng_buf,
                ctlkey_t ctlkey);



// libtlspool_pinentry.c
//
// NOT MAPPED -- callbacks are not part of SWIG's powers

//NOTMAPPED// %rename(pin_service) tlspool_pin_service;
//NOTMAPPED// // int tlspool_pin_service (char *path, uint32_t regflags, int responsetimeout_usec, void (*cb) (struct pioc_pinentry *entry, void *data), void *data);



// libtlspool_lidentry.c
//
// NOT MAPPED -- callbacks are not part of SWIG's powers

//NOTMAPPED// %rename(localid_service) tlspool_localid_service;
//NOTMAPPED// // int tlspool_localid_service (char *path, uint32_t regflags, int responsetimeout, char * (*cb) (lidentry_t *entry, void *data), void *data);


// now, given the renames above, and ignoring the rest, import the definitions

//TODO// %include "../../include/tlspool/starttls.h"
//TODO// %include "../../include/tlspool/commands.h"


