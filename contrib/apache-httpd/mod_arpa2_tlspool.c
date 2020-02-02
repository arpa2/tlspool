/* Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "ap_config.h"
#include "ap_mmn.h"
#include "httpd.h"
#include "http_config.h"
#include "http_connection.h"
#include "http_core.h"
#include "http_log.h"
#include "http_vhost.h"
#include "apr_strings.h"
#include "apr_portable.h"
#include <tlspool/starttls.h>

module AP_MODULE_DECLARE_DATA tlspool_module;

#define strcEQ(s1,s2)    (strcasecmp(s1,s2)    == 0)

/*
 *  the table of configuration directives we provide
 */

#define SSL_CMD_ALL(name, args, desc) \
        AP_INIT_##args("SSL"#name, ssl_cmd_SSL##name, \
                       NULL, RSRC_CONF|OR_AUTHCFG, desc),

#ifndef UNSET
#define UNSET (-1)
#endif

/**
 * Define the SSL verify levels
 */
typedef enum {
    SSL_CVERIFY_UNSET           = UNSET,
    SSL_CVERIFY_NONE            = 0,
    SSL_CVERIFY_OPTIONAL        = 1,
    SSL_CVERIFY_REQUIRE         = 2,
    SSL_CVERIFY_OPTIONAL_NO_CA  = 3
} ssl_verify_t;

static starttls_t tlsdata_srv = {
        .flags = PIOF_STARTTLS_LOCALROLE_SERVER
                | PIOF_STARTTLS_REMOTEROLE_CLIENT
		| PIOF_STARTTLS_LOCALID_CHECK,
        .local = 0,
        .ipproto = IPPROTO_TCP,
        .localid = "",
        .service = "http",
};

static starttls_t tlsdata_now;

typedef struct {
    int          bEnabled;
    ssl_verify_t nVerifyClient;
} tlspool_server_config;

static void trace_nocontext(apr_pool_t *p, const char *file, int line,
                            const char *note)
{
    /*
     * Since we have no request or connection to trace, or any idea
     * from where this routine was called, there's really not much we
     * can do.  If we are not logging everything by way of the
     * EXAMPLE_LOG_EACH constant, do nothing in this routine.
     */

    ap_log_perror(file, line, APLOG_MODULE_INDEX, APLOG_NOTICE, 0, p,
                  APLOGNO(03297) "%s", note);
}

/*
 * Locate our server configuration record for the specified server.
 */
static tlspool_server_config *our_sconfig(const server_rec *s)
{
    return (tlspool_server_config *) ap_get_module_config(s->module_config, &tlspool_module);
}

static tlspool_server_config* pMainConfig;

static void *create_tlspool_server_config(apr_pool_t *p, server_rec *s)
{
   tlspool_server_config *pConfig = apr_pcalloc(p, sizeof *pConfig);

    pConfig->bEnabled = 0;
    pConfig->nVerifyClient = SSL_CVERIFY_NONE;

    char *note = apr_psprintf(p, "create_tlspool_server_config: server_hostname = %s", s->server_hostname);
    if (s->server_hostname == NULL) {
        pMainConfig = pConfig;
    }
    trace_nocontext(p, __FILE__, __LINE__, note);
    return pConfig;
}

static const char *tlspool_on(cmd_parms *cmd, void *dummy, int arg)
{
    char *note;
    tlspool_server_config *pConfig = our_sconfig(cmd->server);

    pConfig->bEnabled = arg;
    note = apr_psprintf(cmd->temp_pool, "tlspool_on arg = %d", arg);
    trace_nocontext(cmd->temp_pool, __FILE__, __LINE__, note);
    ap_directive_t* parent = cmd->directive->parent;
    if (parent == NULL) {
        note = "parent is NULL";
    } else {
        note = apr_psprintf(cmd->temp_pool, "directive = %s, args = %s", parent->directive, parent->args);
    }
    trace_nocontext(cmd->temp_pool, __FILE__, __LINE__, note);
    server_rec* server = cmd->server;
    note = apr_psprintf(cmd->temp_pool, "server_hostname = %s, pConfig = %p", server->server_hostname, pConfig);
    trace_nocontext(cmd->temp_pool, __FILE__, __LINE__, note);
    return NULL;
}

static int func_cb(void* baton, conn_rec *conn, server_rec *s) 
{
    starttls_t *tlsdata = (starttls_t*) baton;
    if (strcEQ(s->server_hostname, tlsdata->localid)) {
        tlspool_server_config *pConfig = our_sconfig(s);
        ssl_verify_t mode = pConfig->nVerifyClient;
        // unset previous set flags;
        tlsdata->flags &= ~(PIOF_STARTTLS_REQUEST_REMOTEID | PIOF_STARTTLS_IGNORE_REMOTEID);
        switch (mode) {
            case SSL_CVERIFY_REQUIRE:
            // default on tlspool_starttls
                break;
            case SSL_CVERIFY_OPTIONAL:
                tlsdata->flags |= PIOF_STARTTLS_REQUEST_REMOTEID;
                break;
            default:
                tlsdata->flags |= PIOF_STARTTLS_IGNORE_REMOTEID;
                break;
        }
        return 1;
    }
    return 0;
}

static char tmp[4096];

typedef struct {
    int plainfd;
    conn_rec *conn;
} privdata_t;

static int namedconnect_vhost (starttls_t *tlsdata, void *p)
{
    privdata_t* privdata = (privdata_t *) p;
strcpy(tmp, tlsdata->localid);
    if (tlsdata->localid[0] != '\0') {
        ap_vhost_iterate_given_conn(privdata->conn, func_cb, tlsdata);
    }

#if !defined(WINDOWS_PORT)
	int soxx[2];
	if (socketpair (AF_UNIX, SOCK_STREAM, 0, soxx) == 0)
#else /* WINDOWS_PORT */
	// https://github.com/ncm/selectable-socketpair
	extern int dumb_socketpair(SOCKET socks[2], int make_overlapped);
	SOCKET soxx[2];
	if (dumb_socketpair(soxx, 1) == 0)
#endif /* WINDOWS_PORT */
	{
		privdata->plainfd = soxx [1];
		return soxx [0];
	}
}

/*
 * This routine is called just after the server accepts the connection,
 * but before it is handed off to a protocol module to be served.  The point
 * of this hook is to allow modules an opportunity to modify the connection
 * as soon as possible. The core server uses this phase to setup the
 * connection record based on the type of connection that is being used.
 *
 * This is a RUN_ALL hook.
 */
static int tlspool_pre_connection(conn_rec *c, void *csd)
{
    char *note;

    if (pMainConfig->bEnabled) {
        apr_socket_t *apr_socket = (apr_socket_t *) csd;
        apr_os_sock_t os_sock;
        apr_os_sock_get(&os_sock, apr_socket);
        int cnx = (int) os_sock;
        privdata_t privdata = { -1, c };

        tlsdata_now = tlsdata_srv;
        switch (pMainConfig->nVerifyClient) {
            case SSL_CVERIFY_REQUIRE:
                // default on tlspool_starttls
                break;
            case SSL_CVERIFY_OPTIONAL:
                tlsdata_now.flags |= PIOF_STARTTLS_REQUEST_REMOTEID;
                break;
            default:
                tlsdata_now.flags |= PIOF_STARTTLS_IGNORE_REMOTEID;
                break;
        }
        note = apr_psprintf(c->pool, "tlspool_pre_connection: c = %pp, pool = %pp, old = %d, nVerifyCLient = %d, flags = 0x%08x",
                        (void*) c, (void*) c->pool, cnx, pMainConfig->nVerifyClient, tlsdata_now.flags);
        trace_nocontext(c->pool, __FILE__, __LINE__, note);
        if (-1 == tlspool_starttls (cnx, &tlsdata_now, &privdata, namedconnect_vhost)) {
            note = apr_psprintf(c->pool, "Failed to STARTTLS on Apache: errno = %d", errno);
            trace_nocontext(c->pool, __FILE__, __LINE__, note);
            if (privdata.plainfd >= 0) {
                close (privdata.plainfd);
            }
            exit (1);
        }
        os_sock = (apr_os_sock_t) privdata.plainfd;
        apr_os_sock_put(&apr_socket, &os_sock, c->pool);

        /*
         * Log the call and exit.
         */
        note = apr_psprintf(c->pool, "tlspool_pre_connection: new = %d, localid = %s", privdata.plainfd, tmp);
        trace_nocontext(c->pool, __FILE__, __LINE__, note);
    } else {
        trace_nocontext(c->pool, __FILE__, __LINE__, "tlspool_pre_connection: TLSPoolEnable off");
    }
    return OK;
}

static const char *ssl_cmd_verify_parse(cmd_parms *parms,
                                        const char *arg,
                                        ssl_verify_t *id)
{
    if (strcEQ(arg, "none") || strcEQ(arg, "off")) {
        *id = SSL_CVERIFY_NONE;
    }
    else if (strcEQ(arg, "optional")) {
        *id = SSL_CVERIFY_OPTIONAL;
    }
    else if (strcEQ(arg, "require") || strcEQ(arg, "on")) {
        *id = SSL_CVERIFY_REQUIRE;
    }
    else if (strcEQ(arg, "optional_no_ca")) {
        *id = SSL_CVERIFY_OPTIONAL_NO_CA;
    }
    else {
        return apr_pstrcat(parms->temp_pool, parms->cmd->name,
                           ": Invalid argument '", arg, "'",
                           NULL);
    }

    return NULL;
}

const char *ssl_cmd_SSLVerifyClient(cmd_parms *cmd,
                                    void *dcfg,
                                    const char *arg)
{
    tlspool_server_config *pConfig = our_sconfig(cmd->server);

    ssl_verify_t mode = SSL_CVERIFY_NONE;
    const char *err;

    if ((err = ssl_cmd_verify_parse(cmd, arg, &mode))) {
        return err;
    }

    server_rec* server = cmd->server;
    char* server_hostname = server->server_hostname;
    char* note = apr_psprintf(cmd->temp_pool, "ssl_cmd_SSLVerifyClient: server_hostname = %s", server_hostname);
    trace_nocontext(cmd->temp_pool, __FILE__, __LINE__, note);

    pConfig->nVerifyClient = mode;
    return NULL;
}

static const command_rec tlspool_cmds[] =
{
    AP_INIT_FLAG("TLSPoolEnable", tlspool_on, NULL, RSRC_CONF,
                 "Run a tlspool server on this host"),
    SSL_CMD_ALL(VerifyClient, TAKE1,
                "SSL Client verify type "
                "('none', 'optional', 'require', 'optional_no_ca')")
    { NULL }
};

static void register_hooks(apr_pool_t *p)
{
    ap_hook_pre_connection(tlspool_pre_connection, NULL, NULL, APR_HOOK_MIDDLE);
}

AP_DECLARE_MODULE(tlspool) = {
    STANDARD20_MODULE_STUFF,
    NULL,                          /* create per-directory config structure */
    NULL,                          /* merge per-directory config structures */
    create_tlspool_server_config,  /* create per-server config structure */
    NULL,                          /* merge per-server config structures */
    tlspool_cmds,                  /* command apr_table_t */
    register_hooks                 /* register hooks */
};
