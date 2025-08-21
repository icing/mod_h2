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
 
#include <assert.h>

#include <apr_strings.h>
#include <apr_optional.h>
#include <apr_optional_hooks.h>

#include <httpd.h>
#include <http_core.h>
#include <http_config.h>
#include <http_connection.h>
#include <http_protocol.h>
#include <http_ssl.h>
#include <http_log.h>

#include "h2_private.h"
#include "h2.h"

#include "h2_config.h"
#include "h2_conn_ctx.h"
#include "h2_c1.h"
#include "h2_c2.h"
#include "h2_protocol.h"
#include "h2_switch.h"

/*******************************************************************************
 * Once per lifetime init, retrieve optional functions
 */
apr_status_t h2_switch_init(apr_pool_t *pool, server_rec *s)
{
    (void)pool;
    ap_log_error(APLOG_MARK, APLOG_TRACE1, 0, s, "h2_switch init");

    return APR_SUCCESS;
}

static int h2_protocol_propose(conn_rec *c, request_rec *r,
                               server_rec *s,
                               const apr_array_header_t *offers,
                               apr_array_header_t *proposals)
{
    int proposed = 0;
    int is_tls = ap_ssl_conn_is_ssl(c);
    const char *const *protos = is_tls? h2_protocol_ids_tls : h2_protocol_ids_clear;
    
    if (!h2_mpm_supported()) {
        return DECLINED;
    }
    
    if (strcmp(AP_PROTOCOL_HTTP1, ap_get_protocol(c))) {
        /* We do not know how to switch from anything else but http/1.1.
         */
        ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, c, APLOGNO(03083)
                      "protocol switch: current proto != http/1.1, declined");
        return DECLINED;
    }
    
    if (!h2_protocol_is_acceptable_c1(c, r, 0)) {
        ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, c, APLOGNO(03084)
                      "protocol propose: connection requirements not met");
        return DECLINED;
    }
    
    if (r) {
        /* So far, this indicates an HTTP/1 Upgrade header initiated
         * protocol switch. For that, the HTTP2-Settings header needs
         * to be present and valid for the connection.
         */
        const char *p;
        
        if (!h2_c1_can_upgrade(r)) {
            return DECLINED;
        }
         
        p = apr_table_get(r->headers_in, "HTTP2-Settings");
        if (!p) {
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(03085)
                          "upgrade without HTTP2-Settings declined");
            return DECLINED;
        }
        
        p = apr_table_get(r->headers_in, "Connection");
        if (!ap_find_token(r->pool, p, "http2-settings")) {
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(03086)
                          "upgrade without HTTP2-Settings declined");
            return DECLINED;
        }
        
        /* We also allow switching only for requests that have no body.
         */
        p = apr_table_get(r->headers_in, "Content-Length");
        if ((p && strcmp(p, "0"))
            || (!p && apr_table_get(r->headers_in, "Transfer-Encoding"))) {
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(03087)
                          "upgrade with body declined");
            return DECLINED;
        }
    }
    
    while (*protos) {
        /* Add all protocols we know (tls or clear) and that
         * are part of the offerings (if there have been any). 
         */
        if (!offers || ap_array_str_contains(offers, *protos)) {
            ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, c,
                          "proposing protocol '%s'", *protos);
            APR_ARRAY_PUSH(proposals, const char*) = *protos;
            proposed = 1;
        }
        ++protos;
    }
    return proposed? DECLINED : OK;
}

#if AP_HAS_RESPONSE_BUCKETS
static void remove_output_filters_below(ap_filter_t *f, ap_filter_type ftype)
{
    ap_filter_t *fnext;

    while (f && f->frec->ftype < ftype) {
        fnext = f->next;
        ap_remove_output_filter(f);
        f = fnext;
    }
}

static void remove_input_filters_below(ap_filter_t *f, ap_filter_type ftype)
{
    ap_filter_t *fnext;

    while (f && f->frec->ftype < ftype) {
        fnext = f->next;
        ap_remove_input_filter(f);
        f = fnext;
    }
}
#endif

static int h2_protocol_switch(conn_rec *c, request_rec *r, server_rec *s,
                              const char *protocol)
{
    int found = 0;
    const char *const *protos = ap_ssl_conn_is_ssl(c)? h2_protocol_ids_tls : h2_protocol_ids_clear;
    const char *const *p = protos;
    
    (void)s;
    if (!h2_mpm_supported()) {
        return DECLINED;
    }

    while (*p) {
        if (!strcmp(*p, protocol)) {
            found = 1;
            break;
        }
        p++;
    }
    
    if (found) {
        ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, c,
                      "switching protocol to '%s'", protocol);
        h2_conn_ctx_create_for_c1(c, s, protocol);

        if (r != NULL) {
            apr_status_t status;
#if AP_HAS_RESPONSE_BUCKETS
            /* Switching in the middle of a request means that
             * we have to send out the response to this one in h2
             * format. So we need to take over the connection
             * and remove all old filters with type up to the
             * CONNEDCTION/NETWORK ones.
             */
            remove_input_filters_below(r->input_filters, AP_FTYPE_CONNECTION);
            remove_output_filters_below(r->output_filters, AP_FTYPE_CONNECTION);
#else
            /* Switching in the middle of a request means that
             * we have to send out the response to this one in h2
             * format. So we need to take over the connection
             * right away.
             */
            ap_remove_input_filter_byhandle(r->input_filters, "http_in");
            ap_remove_output_filter_byhandle(r->output_filters, "HTTP_HEADER");
#endif
            /* Ok, start an h2_conn on this one. */
            status = h2_c1_setup(c, r, s);
            
            if (status != APR_SUCCESS) {
                ap_log_rerror(APLOG_MARK, APLOG_DEBUG, status, r, APLOGNO(03088)
                              "session setup");
                h2_conn_ctx_detach(c);
                return !OK;
            }
            
            h2_c1_run(c);
        }
        return OK;
    }
    
    return DECLINED;
}

static const char *h2_protocol_get(const conn_rec *c)
{
    h2_conn_ctx_t *ctx;

    if (c->master) {
        c = c->master;
    }
    ctx = h2_conn_ctx_get(c);
    return ctx? ctx->protocol : NULL;
}

void h2_switch_register_hooks(void)
{
    ap_hook_protocol_propose(h2_protocol_propose, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_protocol_switch(h2_protocol_switch, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_protocol_get(h2_protocol_get, NULL, NULL, APR_HOOK_MIDDLE);
}
