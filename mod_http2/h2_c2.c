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
#include <stddef.h>

#include <apr_atomic.h>
#include <apr_strings.h>

#include <httpd.h>
#include <http_core.h>
#include <http_config.h>
#include <http_connection.h>
#include <http_protocol.h>
#include <http_request.h>
#include <http_log.h>
#include <http_vhost.h>
#include <util_filter.h>
#include <ap_mmn.h>
#include <ap_mpm.h>
#include <mpm_common.h>
#include <mod_core.h>
#include <scoreboard.h>

#include "h2_private.h"
#include "h2.h"
#include "h2_bucket_beam.h"
#include "h2_c1.h"
#include "h2_config.h"
#include "h2_conn_ctx.h"
#include "h2_c2_filter.h"
#include "h2_protocol.h"
#include "h2_mplx.h"
#include "h2_request.h"
#include "h2_headers.h"
#include "h2_session.h"
#include "h2_stream.h"
#include "h2_ws.h"
#include "h2_c2.h"
#include "h2_util.h"
#include "mod_http2.h"


static module *mpm_module;
static int mpm_supported = 1;
static apr_socket_t *dummy_socket;

#if AP_HAS_RESPONSE_BUCKETS

static ap_filter_rec_t *c2_net_in_filter_handle;
static ap_filter_rec_t *c2_net_out_filter_handle;
static ap_filter_rec_t *c2_request_in_filter_handle;
static ap_filter_rec_t *c2_notes_out_filter_handle;

#endif /* AP_HAS_RESPONSE_BUCKETS */

static void check_modules(int force)
{
    static int checked = 0;
    int i;

    if (force || !checked) {
        for (i = 0; ap_loaded_modules[i]; ++i) {
            module *m = ap_loaded_modules[i];

            if (!strcmp("event.c", m->name)) {
                mpm_module = m;
                break;
            }
            else if (!strcmp("motorz.c", m->name)) {
                mpm_module = m;
                break;
            }
            else if (!strcmp("mpm_netware.c", m->name)) {
                mpm_module = m;
                break;
            }
            else if (!strcmp("prefork.c", m->name)) {
                mpm_module = m;
                /* While http2 can work really well on prefork, it collides
                 * today's use case for prefork: running single-thread app engines
                 * like php. If we restrict h2_workers to 1 per process, php will
                 * work fine, but browser will be limited to 1 active request at a
                 * time. */
                mpm_supported = 0;
                break;
            }
            else if (!strcmp("simple_api.c", m->name)) {
                mpm_module = m;
                mpm_supported = 0;
                break;
            }
            else if (!strcmp("mpm_winnt.c", m->name)) {
                mpm_module = m;
                break;
            }
            else if (!strcmp("worker.c", m->name)) {
                mpm_module = m;
                break;
            }
        }
        checked = 1;
    }
}

const char *h2_conn_mpm_name(void)
{
    check_modules(0);
    return mpm_module? mpm_module->name : "unknown";
}

int h2_mpm_supported(void)
{
    check_modules(0);
    return mpm_supported;
}

apr_status_t h2_c2_child_init(apr_pool_t *pool, server_rec *s)
{
    check_modules(1);
    return apr_socket_create(&dummy_socket, APR_INET, SOCK_STREAM,
                             APR_PROTO_TCP, pool);
}

static void h2_c2_log_io(conn_rec *c2, apr_off_t bytes_sent)
{
    if (bytes_sent && h2_c_logio_add_bytes_out) {
        h2_c_logio_add_bytes_out(c2, bytes_sent);
    }
}

void h2_c2_destroy(conn_rec *c2)
{
    h2_conn_ctx_t *conn_ctx = h2_conn_ctx_get(c2);

    ap_log_cerror(APLOG_MARK, APLOG_TRACE3, 0, c2,
                  "h2_c2(%s): destroy", c2->log_id);
    if(!c2->aborted && conn_ctx && conn_ctx->bytes_sent) {
      h2_c2_log_io(c2, conn_ctx->bytes_sent);
    }
    apr_pool_destroy(c2->pool);
}

void h2_c2_abort(conn_rec *c2, conn_rec *from)
{
    h2_conn_ctx_t *conn_ctx = h2_conn_ctx_get(c2);

    AP_DEBUG_ASSERT(conn_ctx);
    AP_DEBUG_ASSERT(conn_ctx->stream_id);
    if(!c2->aborted && conn_ctx->bytes_sent) {
      h2_c2_log_io(c2, conn_ctx->bytes_sent);
    }

    if (conn_ctx->beam_in) {
        h2_beam_abort(conn_ctx->beam_in, from);
    }
    if (conn_ctx->beam_out) {
        h2_beam_abort(conn_ctx->beam_out, from);
    }
    c2->aborted = 1;
}

typedef struct {
    apr_bucket_brigade *bb;       /* c2: data in holding area */
    unsigned did_upgrade_eos:1;   /* for Upgrade, we added an extra EOS */
} h2_c2_fctx_in_t;

static apr_status_t h2_c2_filter_in(ap_filter_t* f,
                                           apr_bucket_brigade* bb,
                                           ap_input_mode_t mode,
                                           apr_read_type_e block,
                                           apr_off_t readbytes)
{
    h2_conn_ctx_t *conn_ctx;
    h2_c2_fctx_in_t *fctx = f->ctx;
    apr_status_t status = APR_SUCCESS;
    apr_bucket *b;
    apr_off_t bblen;
    apr_size_t rmax = (readbytes < APR_INT32_MAX)?
                       (apr_size_t)readbytes : APR_INT32_MAX;
    
    conn_ctx = h2_conn_ctx_get(f->c);
    AP_DEBUG_ASSERT(conn_ctx);

    if (mode == AP_MODE_INIT) {
        return ap_get_brigade(f->c->input_filters, bb, mode, block, readbytes);
    }
    
    if (f->c->aborted) {
        return APR_ECONNABORTED;
    }
    
    if (APLOGctrace3(f->c)) {
        ap_log_cerror(APLOG_MARK, APLOG_TRACE3, 0, f->c,
                      "h2_c2_in(%s-%d): read, mode=%d, block=%d, readbytes=%ld",
                      conn_ctx->id, conn_ctx->stream_id, mode, block,
                      (long)readbytes);
    }

    if (!fctx) {
        fctx = apr_pcalloc(f->c->pool, sizeof(*fctx));
        f->ctx = fctx;
        fctx->bb = apr_brigade_create(f->c->pool, f->c->bucket_alloc);
        if (!conn_ctx->beam_in) {
            b = apr_bucket_eos_create(f->c->bucket_alloc);
            APR_BRIGADE_INSERT_TAIL(fctx->bb, b);
        }
    }

    /* If this is a HTTP Upgrade, it means the request we process
     * has not Content, although the stream is not necessarily closed.
     * On first read, we insert an EOS to signal processing that it
     * has the complete body. */
    if (conn_ctx->is_upgrade && !fctx->did_upgrade_eos) {
        b = apr_bucket_eos_create(f->c->bucket_alloc);
        APR_BRIGADE_INSERT_TAIL(fctx->bb, b);
        fctx->did_upgrade_eos = 1;
    }

    while (APR_BRIGADE_EMPTY(fctx->bb)) {
        /* Get more input data for our request. */
        if (APLOGctrace2(f->c)) {
            ap_log_cerror(APLOG_MARK, APLOG_TRACE2, status, f->c,
                          "h2_c2_in(%s-%d): get more data from mplx, block=%d, "
                          "readbytes=%ld",
                          conn_ctx->id, conn_ctx->stream_id, block, (long)readbytes);
        }
        if (conn_ctx->beam_in) {
            if (conn_ctx->pipe_in[H2_PIPE_OUT]) {
receive:
                status = h2_beam_receive(conn_ctx->beam_in, f->c, fctx->bb, APR_NONBLOCK_READ,
                                         conn_ctx->mplx->stream_max_mem);
                if (APR_STATUS_IS_EAGAIN(status) && APR_BLOCK_READ == block) {
                    status = h2_util_wait_on_pipe(conn_ctx->pipe_in[H2_PIPE_OUT]);
                    if (APR_SUCCESS == status) {
                        goto receive;
                    }
                }
            }
            else {
                status = h2_beam_receive(conn_ctx->beam_in, f->c, fctx->bb, block,
                                         conn_ctx->mplx->stream_max_mem);
            }
        }
        else {
            status = APR_EOF;
        }
        
        if (APLOGctrace3(f->c)) {
            ap_log_cerror(APLOG_MARK, APLOG_TRACE3, status, f->c,
                          "h2_c2_in(%s-%d): read returned",
                          conn_ctx->id, conn_ctx->stream_id);
        }
        if (APR_STATUS_IS_EAGAIN(status) 
            && (mode == AP_MODE_GETLINE || block == APR_BLOCK_READ)) {
            /* chunked input handling does not seem to like it if we
             * return with APR_EAGAIN from a GETLINE read... 
             * upload 100k test on test-ser.example.org hangs */
            status = APR_SUCCESS;
        }
        else if (APR_STATUS_IS_EOF(status)) {
            break;
        }
        else if (status != APR_SUCCESS) {
            conn_ctx->last_err = status;
            return status;
        }

        if (APLOGctrace3(f->c)) {
            h2_util_bb_log(f->c, conn_ctx->stream_id, APLOG_TRACE3,
                        "c2 input recv raw", fctx->bb);
        }
        if (h2_c_logio_add_bytes_in) {
            apr_brigade_length(bb, 0, &bblen);
            h2_c_logio_add_bytes_in(f->c, bblen);
        }
    }
    
    /* Nothing there, no more data to get. Return. */
    if (status == APR_EOF && APR_BRIGADE_EMPTY(fctx->bb)) {
        return status;
    }

    if (APLOGctrace3(f->c)) {
        h2_util_bb_log(f->c, conn_ctx->stream_id, APLOG_TRACE3,
                    "c2 input.bb", fctx->bb);
    }
           
    if (APR_BRIGADE_EMPTY(fctx->bb)) {
        if (APLOGctrace3(f->c)) {
            ap_log_cerror(APLOG_MARK, APLOG_TRACE3, 0, f->c,
                          "h2_c2_in(%s-%d): no data",
                          conn_ctx->id, conn_ctx->stream_id);
        }
        return (block == APR_NONBLOCK_READ)? APR_EAGAIN : APR_EOF;
    }
    
    if (mode == AP_MODE_EXHAUSTIVE) {
        /* return all we have */
        APR_BRIGADE_CONCAT(bb, fctx->bb);
    }
    else if (mode == AP_MODE_READBYTES) {
        status = h2_brigade_concat_length(bb, fctx->bb, rmax);
    }
    else if (mode == AP_MODE_SPECULATIVE) {
        status = h2_brigade_copy_length(bb, fctx->bb, rmax);
    }
    else if (mode == AP_MODE_GETLINE) {
        /* we are reading a single LF line, e.g. the HTTP headers. 
         * this has the nasty side effect to split the bucket, even
         * though it ends with CRLF and creates a 0 length bucket */
        status = apr_brigade_split_line(bb, fctx->bb, block,
                                        HUGE_STRING_LEN);
        if (APLOGctrace3(f->c)) {
            char buffer[1024];
            apr_size_t len = sizeof(buffer)-1;
            apr_brigade_flatten(bb, buffer, &len);
            buffer[len] = 0;
            ap_log_cerror(APLOG_MARK, APLOG_TRACE3, status, f->c,
                          "h2_c2_in(%s-%d): getline: %s",
                          conn_ctx->id, conn_ctx->stream_id, buffer);
        }
    }
    else {
        /* Hmm, well. There is mode AP_MODE_EATCRLF, but we chose not
         * to support it. Seems to work. */
        ap_log_cerror(APLOG_MARK, APLOG_ERR, APR_ENOTIMPL, f->c,
                      APLOGNO(03472) 
                      "h2_c2_in(%s-%d), unsupported READ mode %d",
                      conn_ctx->id, conn_ctx->stream_id, mode);
        status = APR_ENOTIMPL;
    }
    
    if (APLOGctrace3(f->c)) {
        apr_brigade_length(bb, 0, &bblen);
        ap_log_cerror(APLOG_MARK, APLOG_TRACE3, status, f->c,
                      "h2_c2_in(%s-%d): %ld data bytes",
                      conn_ctx->id, conn_ctx->stream_id, (long)bblen);
    }
    return status;
}

static apr_status_t beam_out(conn_rec *c2, h2_conn_ctx_t *conn_ctx, apr_bucket_brigade* bb)
{
    apr_off_t written = 0;
    apr_status_t rv;

    rv = h2_beam_send(conn_ctx->beam_out, c2, bb, APR_BLOCK_READ, &written);
    if (APR_STATUS_IS_EAGAIN(rv)) {
        rv = APR_SUCCESS;
    }
    return rv;
}

static apr_status_t h2_c2_filter_out(ap_filter_t* f, apr_bucket_brigade* bb)
{
    h2_conn_ctx_t *conn_ctx = h2_conn_ctx_get(f->c);
    apr_status_t rv;

   if (bb == NULL) {
#if !AP_MODULE_MAGIC_AT_LEAST(20180720, 1)
        f->c->data_in_output_filters = 0;
#endif
        return APR_SUCCESS;
    }

    ap_assert(conn_ctx);
#if AP_HAS_RESPONSE_BUCKETS
    if (!conn_ctx->has_final_response) {
        apr_bucket *e;

        for (e = APR_BRIGADE_FIRST(bb);
             e != APR_BRIGADE_SENTINEL(bb);
             e = APR_BUCKET_NEXT(e))
        {
            if (AP_BUCKET_IS_RESPONSE(e)) {
                ap_bucket_response *resp = e->data;
                if (resp->status >= 200) {
                    conn_ctx->has_final_response = 1;
                    break;
                }
            }
            if (APR_BUCKET_IS_EOS(e)) {
                break;
            }
        }
    }
#endif /* AP_HAS_RESPONSE_BUCKETS */
    rv = beam_out(f->c, conn_ctx, bb);

    ap_log_cerror(APLOG_MARK, APLOG_TRACE2, rv, f->c,
                  "h2_c2(%s-%d): output leave",
                  conn_ctx->id, conn_ctx->stream_id);
    if (APR_SUCCESS != rv) {
        h2_c2_abort(f->c, f->c);
    }
    return rv;
}

static int addn_headers(void *udata, const char *name, const char *value)
{
    apr_table_t *dest = udata;
    apr_table_addn(dest, name, value);
    return 1;
}

static void check_early_hints(request_rec *r, const char *tag)
{
    apr_array_header_t *push_list = h2_config_push_list(r);
    apr_table_t *early_headers = h2_config_early_headers(r);

    if (!r->expecting_100 &&
        ((push_list && push_list->nelts > 0) ||
         (early_headers && !apr_is_empty_table(early_headers)))) {
        int have_hints = 0, i;

        if (push_list && push_list->nelts > 0) {
            ap_log_rerror(APLOG_MARK, APLOG_TRACE1, 0, r,
                          "%s, early announcing %d resources for push",
                          tag, push_list->nelts);
            for (i = 0; i < push_list->nelts; ++i) {
                h2_push_res *push = &APR_ARRAY_IDX(push_list, i, h2_push_res);
                apr_table_add(r->headers_out, "Link",
                               apr_psprintf(r->pool, "<%s>; rel=preload%s",
                                            push->uri_ref, push->critical? "; critical" : ""));
            }
            have_hints = 1;
        }
        if (early_headers && !apr_is_empty_table(early_headers)) {
            apr_table_do(addn_headers, r->headers_out, early_headers, NULL);
            have_hints = 1;
        }

        if (have_hints) {
          int old_status;
          const char *old_line;

          if (h2_config_rgeti(r, H2_CONF_PUSH) == 0 &&
              h2_config_sgeti(r->server, H2_CONF_PUSH) != 0) {
              apr_table_setn(r->connection->notes, H2_PUSH_MODE_NOTE, "0");
          }
          old_status = r->status;
          old_line = r->status_line;
          r->status = 103;
          r->status_line = "103 Early Hints";
          ap_send_interim_response(r, 1);
          r->status = old_status;
          r->status_line = old_line;
        }
    }
}

static int c2_hook_fixups(request_rec *r)
{
    conn_rec *c2 = r->connection;
    h2_conn_ctx_t *conn_ctx;

    if (!c2->master || !(conn_ctx = h2_conn_ctx_get(c2)) || !conn_ctx->stream_id) {
        return DECLINED;
    }

    check_early_hints(r, "late_fixup");

    return DECLINED;
}

static apr_status_t http2_get_pollfd_from_conn(conn_rec *c,
                                               struct apr_pollfd_t *pfd,
                                               apr_interval_time_t *ptimeout)
{
#if H2_USE_PIPES
    if (c->master) {
        h2_conn_ctx_t *ctx = h2_conn_ctx_get(c);
        if (ctx) {
            if (ctx->beam_in && ctx->pipe_in[H2_PIPE_OUT]) {
                pfd->desc_type = APR_POLL_FILE;
                pfd->desc.f = ctx->pipe_in[H2_PIPE_OUT];
                if (ptimeout)
                    *ptimeout = h2_beam_timeout_get(ctx->beam_in);
            }
            else {
                /* no input */
                pfd->desc_type = APR_NO_DESC;
                if (ptimeout)
                    *ptimeout = -1;
            }
            return APR_SUCCESS;
        }
    }
#else
    (void)c;
    (void)pfd;
    (void)ptimeout;
#endif /* H2_USE_PIPES */
    return APR_ENOTIMPL;
}

#if AP_HAS_RESPONSE_BUCKETS

static void c2_pre_read_request(request_rec *r, conn_rec *c2)
{
    h2_conn_ctx_t *conn_ctx;

    if (!c2->master || !(conn_ctx = h2_conn_ctx_get(c2)) || !conn_ctx->stream_id) {
        return;
    }
    ap_log_rerror(APLOG_MARK, APLOG_TRACE3, 0, r,
                  "h2_c2(%s-%d): adding request filters",
                  conn_ctx->id, conn_ctx->stream_id);
    ap_add_input_filter_handle(c2_request_in_filter_handle, NULL, r, r->connection);
    ap_add_output_filter_handle(c2_notes_out_filter_handle, NULL, r, r->connection);
}

static int c2_post_read_request(request_rec *r)
{
    h2_conn_ctx_t *conn_ctx;
    conn_rec *c2 = r->connection;
    apr_time_t timeout;

    if (!c2->master || !(conn_ctx = h2_conn_ctx_get(c2)) || !conn_ctx->stream_id) {
        return DECLINED;
    }
    /* Now that the request_rec is fully initialized, set relevant params */
    conn_ctx->server = r->server;
    timeout = h2_config_geti64(r, r->server, H2_CONF_STREAM_TIMEOUT);
    if (timeout <= 0) {
        timeout = r->server->timeout;
    }
    h2_conn_ctx_set_timeout(conn_ctx, timeout);
    /* We only handle this one request on the connection and tell everyone
     * that there is no need to keep it "clean" if something fails. Also,
     * this prevents mod_reqtimeout from doing funny business with monitoring
     * keepalive timeouts.
     */
    r->connection->keepalive = AP_CONN_CLOSE;

    if (conn_ctx->beam_in && !apr_table_get(r->headers_in, "Content-Length")) {
        r->body_indeterminate = 1;
    }

    if (h2_config_sgeti(conn_ctx->server, H2_CONF_COPY_FILES)) {
        ap_log_rerror(APLOG_MARK, APLOG_TRACE1, 0, r,
                      "h2_mplx(%s-%d): copy_files in output",
                      conn_ctx->id, conn_ctx->stream_id);
        h2_beam_set_copy_files(conn_ctx->beam_out, 1);
    }

    /* Add the raw bytes of the request (e.g. header frame lengths to
     * the logio for this request. */
    if (conn_ctx->request->raw_bytes && h2_c_logio_add_bytes_in) {
        h2_c_logio_add_bytes_in(c2, conn_ctx->request->raw_bytes);
    }
    return OK;
}

static int c2_hook_pre_connection(conn_rec *c2, void *csd)
{
    h2_conn_ctx_t *conn_ctx;

    if (!c2->master || !(conn_ctx = h2_conn_ctx_get(c2)) || !conn_ctx->stream_id) {
        return DECLINED;
    }

    ap_log_cerror(APLOG_MARK, APLOG_TRACE2, 0, c2,
                  "h2_c2(%s-%d), adding filters",
                  conn_ctx->id, conn_ctx->stream_id);
    ap_add_input_filter_handle(c2_net_in_filter_handle, NULL, NULL, c2);
    ap_add_output_filter_handle(c2_net_out_filter_handle, NULL, NULL, c2);
    if (c2->keepalives == 0) {
        /* Simulate that we had already a request on this connection. Some
         * hooks trigger special behaviour when keepalives is 0.
         * (Not necessarily in pre_connection, but later. Set it here, so it
         * is in place.) */
        c2->keepalives = 1;
        /* We signal that this connection will be closed after the request.
         * Which is true in that sense that we throw away all traffic data
         * on this c2 connection after each requests. Although we might
         * reuse internal structures like memory pools.
         * The wanted effect of this is that httpd does not try to clean up
         * any dangling data on this connection when a request is done. Which
         * is unnecessary on a h2 stream.
         */
        c2->keepalive = AP_CONN_CLOSE;
    }
    return OK;
}

void h2_c2_register_hooks(void)
{
    /* When the connection processing actually starts, we might
     * take over, if the connection is for a h2 stream.
     */
    ap_hook_pre_connection(c2_hook_pre_connection,
                           NULL, NULL, APR_HOOK_MIDDLE);

    /* We need to manipulate the standard HTTP/1.1 protocol filters and
     * install our own. This needs to be done very early. */
    ap_hook_pre_read_request(c2_pre_read_request, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_post_read_request(c2_post_read_request, NULL, NULL,
                              APR_HOOK_REALLY_FIRST);
    ap_hook_fixups(c2_hook_fixups, NULL, NULL, APR_HOOK_LAST);
#if H2_USE_POLLFD_FROM_CONN
    ap_hook_get_pollfd_from_conn(http2_get_pollfd_from_conn, NULL, NULL,
                                 APR_HOOK_MIDDLE);
#endif
    APR_REGISTER_OPTIONAL_FN(http2_get_pollfd_from_conn);

    c2_net_in_filter_handle =
        ap_register_input_filter("H2_C2_NET_IN", h2_c2_filter_in,
                                 NULL, AP_FTYPE_NETWORK);
    c2_net_out_filter_handle =
        ap_register_output_filter("H2_C2_NET_OUT", h2_c2_filter_out,
                                  NULL, AP_FTYPE_NETWORK);
    c2_request_in_filter_handle =
        ap_register_input_filter("H2_C2_REQUEST_IN", h2_c2_filter_request_in,
                                 NULL, AP_FTYPE_PROTOCOL);
    c2_notes_out_filter_handle =
        ap_register_output_filter("H2_C2_NOTES_OUT", h2_c2_filter_notes_out,
                                  NULL, AP_FTYPE_PROTOCOL);
}

#else /* AP_HAS_RESPONSE_BUCKETS */

static apr_status_t c2_run_pre_connection(conn_rec *c2, apr_socket_t *csd)
{
    if (c2->keepalives == 0) {
        /* Simulate that we had already a request on this connection. Some
         * hooks trigger special behaviour when keepalives is 0.
         * (Not necessarily in pre_connection, but later. Set it here, so it
         * is in place.) */
        c2->keepalives = 1;
        /* We signal that this connection will be closed after the request.
         * Which is true in that sense that we throw away all traffic data
         * on this c2 connection after each requests. Although we might
         * reuse internal structures like memory pools.
         * The wanted effect of this is that httpd does not try to clean up
         * any dangling data on this connection when a request is done. Which
         * is unnecessary on a h2 stream.
         */
        c2->keepalive = AP_CONN_CLOSE;
        return ap_run_pre_connection(c2, csd);
    }
    ap_assert(c2->output_filters);
    return APR_SUCCESS;
}

apr_status_t h2_c2_process(conn_rec *c2, apr_thread_t *thread, int worker_id)
{
    h2_conn_ctx_t *conn_ctx = h2_conn_ctx_get(c2);

    ap_assert(conn_ctx);
    ap_assert(conn_ctx->mplx);

    /* See the discussion at <https://github.com/icing/mod_h2/issues/195>
     *
     * Each conn_rec->id is supposed to be unique at a point in time. Since
     * some modules (and maybe external code) uses this id as an identifier
     * for the request_rec they handle, it needs to be unique for secondary
     * connections also.
     *
     * The MPM module assigns the connection ids and mod_unique_id is using
     * that one to generate identifier for requests. While the implementation
     * works for HTTP/1.x, the parallel execution of several requests per
     * connection will generate duplicate identifiers on load.
     *
     * The original implementation for secondary connection identifiers used
     * to shift the master connection id up and assign the stream id to the
     * lower bits. This was cramped on 32 bit systems, but on 64bit there was
     * enough space.
     *
     * As issue 195 showed, mod_unique_id only uses the lower 32 bit of the
     * connection id, even on 64bit systems. Therefore collisions in request ids.
     *
     * The way master connection ids are generated, there is some space "at the
     * top" of the lower 32 bits on allmost all systems. If you have a setup
     * with 64k threads per child and 255 child processes, you live on the edge.
     *
     * The new implementation shifts 8 bits and XORs in the worker
     * id. This will experience collisions with > 256 h2 workers and heavy
     * load still. There seems to be no way to solve this in all possible
     * configurations by mod_h2 alone.
     */
    c2->id = (c2->master->id << 8)^worker_id;

    if (!conn_ctx->pre_conn_done) {
        ap_log_cerror(APLOG_MARK, APLOG_TRACE2, 0, c2,
                      "h2_c2(%s-%d), adding filters",
                      conn_ctx->id, conn_ctx->stream_id);
        ap_add_input_filter("H2_C2_NET_IN", NULL, NULL, c2);
        ap_add_output_filter("H2_C2_NET_CATCH_H1", NULL, NULL, c2);
        ap_add_output_filter("H2_C2_NET_OUT", NULL, NULL, c2);

        c2_run_pre_connection(c2, ap_get_conn_socket(c2));
        conn_ctx->pre_conn_done = 1;
    }

    ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, c2,
                  "h2_c2(%s-%d): process connection",
                  conn_ctx->id, conn_ctx->stream_id);

    c2->current_thread = thread;
    ap_run_process_connection(c2);

    ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, c2,
                  "h2_c2(%s-%d): processing done",
                  conn_ctx->id, conn_ctx->stream_id);

    return APR_SUCCESS;
}

static apr_status_t c2_process(h2_conn_ctx_t *conn_ctx, conn_rec *c)
{
    const h2_request *req = conn_ctx->request;
    conn_state_t *cs = c->cs;
    request_rec *r = NULL;
    const char *tenc;
    apr_time_t timeout;
    apr_status_t rv = APR_SUCCESS;

    if (req->protocol && !strcmp("websocket", req->protocol)) {
        req = h2_ws_rewrite_request(req, c, conn_ctx->beam_in == NULL);
        if (!req) {
            rv = APR_EGENERAL;
            goto cleanup;
        }
    }

    r = h2_create_request_rec(req, c, conn_ctx->beam_in == NULL);

    if (!r) {
        ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, c,
                      "h2_c2(%s-%d): create request_rec failed, r=NULL",
                      conn_ctx->id, conn_ctx->stream_id);
        goto cleanup;
    }
    if (r->status != HTTP_OK) {
        ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, c,
                      "h2_c2(%s-%d): create request_rec failed, r->status=%d",
                      conn_ctx->id, conn_ctx->stream_id, r->status);
        goto cleanup;
    }

    tenc = apr_table_get(r->headers_in, "Transfer-Encoding");
    conn_ctx->input_chunked = tenc && ap_is_chunked(r->pool, tenc);

    ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, c,
                  "h2_c2(%s-%d): created request_rec for %s",
                  conn_ctx->id, conn_ctx->stream_id, r->the_request);
    conn_ctx->server = r->server;
    timeout = h2_config_geti64(r, r->server, H2_CONF_STREAM_TIMEOUT);
    if (timeout <= 0) {
        timeout = r->server->timeout;
    }
    h2_conn_ctx_set_timeout(conn_ctx, timeout);

    if (h2_config_sgeti(conn_ctx->server, H2_CONF_COPY_FILES)) {
        ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, c,
                      "h2_mplx(%s-%d): copy_files in output",
                      conn_ctx->id, conn_ctx->stream_id);
        h2_beam_set_copy_files(conn_ctx->beam_out, 1);
    }

    ap_update_child_status(c->sbh, SERVER_BUSY_WRITE, r);
    if (cs) {
        cs->state = CONN_STATE_HANDLER;
    }
    ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, c,
                  "h2_c2(%s-%d): start process_request",
                  conn_ctx->id, conn_ctx->stream_id);

    /* Add the raw bytes of the request (e.g. header frame lengths to
     * the logio for this request. */
    if (req->raw_bytes && h2_c_logio_add_bytes_in) {
        h2_c_logio_add_bytes_in(c, req->raw_bytes);
    }

    ap_process_request(r);
    /* After the call to ap_process_request, the
     * request pool may have been deleted. */
    r = NULL;
    if (conn_ctx->beam_out) {
        h2_beam_close(conn_ctx->beam_out, c);
    }

    ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, c,
                  "h2_c2(%s-%d): process_request done",
                  conn_ctx->id, conn_ctx->stream_id);
    if (cs)
        cs->state = CONN_STATE_WRITE_COMPLETION;

cleanup:
    return rv;
}

conn_rec *h2_c2_create(conn_rec *c1, apr_pool_t *parent,
                       apr_bucket_alloc_t *buckt_alloc)
{
    apr_pool_t *pool;
    conn_rec *c2;
    void *cfg;

    ap_assert(c1);
    ap_log_cerror(APLOG_MARK, APLOG_TRACE3, 0, c1,
                  "h2_c2: create for c1(%ld)", c1->id);

    /* We create a pool with its own allocator to be used for
     * processing a request. This is the only way to have the processing
     * independent of its parent pool in the sense that it can work in
     * another thread.
     */
    apr_pool_create(&pool, parent);
    apr_pool_tag(pool, "h2_c2_conn");

    c2 = (conn_rec *) apr_palloc(pool, sizeof(conn_rec));
    memcpy(c2, c1, sizeof(conn_rec));

    c2->master                 = c1;
    c2->pool                   = pool;
    c2->conn_config            = ap_create_conn_config(pool);
    c2->notes                  = apr_table_make(pool, 5);
    c2->input_filters          = NULL;
    c2->output_filters         = NULL;
    c2->keepalives             = 0;
#if AP_MODULE_MAGIC_AT_LEAST(20180903, 1)
    c2->filter_conn_ctx        = NULL;
#endif
    c2->bucket_alloc           = apr_bucket_alloc_create(pool);
#if !AP_MODULE_MAGIC_AT_LEAST(20180720, 1)
    c2->data_in_input_filters  = 0;
    c2->data_in_output_filters = 0;
#endif
    /* prevent mpm_event from making wrong assumptions about this connection,
     * like e.g. using its socket for an async read check. */
    c2->clogging_input_filters = 1;
    c2->log                    = NULL;
    c2->aborted                = 0;
    /* We cannot install the master connection socket on the secondary, as
     * modules mess with timeouts/blocking of the socket, with
     * unwanted side effects to the master connection processing.
     * Fortunately, since we never use the secondary socket, we can just install
     * a single, process-wide dummy and everyone is happy.
     */
    ap_set_module_config(c2->conn_config, &core_module, dummy_socket);
    /* TODO: these should be unique to this thread */
    c2->sbh = NULL; /*c1->sbh;*/
    /* TODO: not all mpm modules have learned about secondary connections yet.
     * copy their config from master to secondary.
     */
    if (mpm_module) {
        cfg = ap_get_module_config(c1->conn_config, mpm_module);
        ap_set_module_config(c2->conn_config, mpm_module, cfg);
    }

    ap_log_cerror(APLOG_MARK, APLOG_TRACE3, 0, c2,
                  "h2_c2(%s): created", c2->log_id);
    return c2;
}

static int h2_c2_hook_post_read_request(request_rec *r)
{
    h2_conn_ctx_t *conn_ctx = h2_conn_ctx_get(r->connection);

    if (conn_ctx && conn_ctx->stream_id && ap_is_initial_req(r)) {

        ap_log_rerror(APLOG_MARK, APLOG_TRACE3, 0, r,
                      "h2_c2(%s-%d): adding request filters",
                      conn_ctx->id, conn_ctx->stream_id);

        /* setup the correct filters to process the request for h2 */
        ap_add_input_filter("H2_C2_REQUEST_IN", NULL, r, r->connection);

        /* replace the core http filter that formats response headers
         * in HTTP/1 with our own that collects status and headers */
        ap_remove_output_filter_byhandle(r->output_filters, "HTTP_HEADER");

        ap_add_output_filter("H2_C2_RESPONSE_OUT", NULL, r, r->connection);
        ap_add_output_filter("H2_C2_TRAILERS_OUT", NULL, r, r->connection);
    }
    return DECLINED;
}

static int h2_c2_hook_process(conn_rec* c)
{
    h2_conn_ctx_t *ctx;

    if (!c->master) {
        return DECLINED;
    }

    ctx = h2_conn_ctx_get(c);
    if (ctx->stream_id) {
        ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, c,
                      "h2_h2, processing request directly");
        c2_process(ctx, c);
        return DONE;
    }
    else {
        ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, c,
                      "secondary_conn(%ld): no h2 stream assing?", c->id);
    }
    return DECLINED;
}

void h2_c2_register_hooks(void)
{
    /* When the connection processing actually starts, we might
     * take over, if the connection is for a h2 stream.
     */
    ap_hook_process_connection(h2_c2_hook_process,
                               NULL, NULL, APR_HOOK_FIRST);
    /* We need to manipulate the standard HTTP/1.1 protocol filters and
     * install our own. This needs to be done very early. */
    ap_hook_post_read_request(h2_c2_hook_post_read_request, NULL, NULL, APR_HOOK_REALLY_FIRST);
    ap_hook_fixups(c2_hook_fixups, NULL, NULL, APR_HOOK_LAST);
#if H2_USE_POLLFD_FROM_CONN
    ap_hook_get_pollfd_from_conn(http2_get_pollfd_from_conn, NULL, NULL,
                                 APR_HOOK_MIDDLE);
#endif
    APR_REGISTER_OPTIONAL_FN(http2_get_pollfd_from_conn);

    ap_register_input_filter("H2_C2_NET_IN", h2_c2_filter_in,
                             NULL, AP_FTYPE_NETWORK);
    ap_register_output_filter("H2_C2_NET_OUT", h2_c2_filter_out,
                              NULL, AP_FTYPE_NETWORK);
    ap_register_output_filter("H2_C2_NET_CATCH_H1", h2_c2_filter_catch_h1_out,
                              NULL, AP_FTYPE_NETWORK);

    ap_register_input_filter("H2_C2_REQUEST_IN", h2_c2_filter_request_in,
                             NULL, AP_FTYPE_PROTOCOL);
    ap_register_output_filter("H2_C2_RESPONSE_OUT", h2_c2_filter_response_out,
                              NULL, AP_FTYPE_PROTOCOL);
    ap_register_output_filter("H2_C2_TRAILERS_OUT", h2_c2_filter_trailers_out,
                              NULL, AP_FTYPE_PROTOCOL);
}

#endif /* else AP_HAS_RESPONSE_BUCKETS */
