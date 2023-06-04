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

#include "apr.h"
#include "apr_strings.h"
#include "apr_lib.h"
#include "apr_strmatch.h"

#include <ap_mmn.h>

#include <httpd.h>
#include <http_core.h>
#include <http_connection.h>
#include <http_protocol.h>
#include <http_request.h>
#include <http_log.h>
#include <http_ssl.h>
#include <http_vhost.h>
#include <util_filter.h>
#include <ap_mpm.h>

#include "h2_private.h"
#include "h2_config.h"
#include "h2_conn_ctx.h"
#include "h2_request.h"
#include "h2_ws.h"

request_rec *h2_ws_create_request_rec(const h2_request *req, conn_rec *c2,
                                      int no_body)
{
    h2_conn_ctx_t *conn_ctx = h2_conn_ctx_get(c2);
    h2_request *wsreq;
    request_rec *r = NULL;

    if (!conn_ctx || !req->protocol || strcmp("websocket", req->protocol))
        goto leave;

    if (apr_strnatcasecmp("CONNECT", req->method)) {
        ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, c2,
                      "h2_c2(%s-%d): websocket request with method %s",
                      conn_ctx->id, conn_ctx->stream_id, req->method);
        goto leave;
    }
    if (!req->scheme) {
        ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, c2,
                      "h2_c2(%s-%d): websocket CONNECT without :scheme",
                      conn_ctx->id, conn_ctx->stream_id);
        goto leave;
    }
    if (!req->path) {
        ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, c2,
                      "h2_c2(%s-%d): websocket CONNECT without :path",
                      conn_ctx->id, conn_ctx->stream_id);
        goto leave;
    }

    /* Transform the HTTP/2 extended CONNECT to an internal GET using
     * the HTTP/1.1 version of websocket connection setup. */
    wsreq = h2_request_clone(c2->pool, req);
    wsreq->method = "GET";
    apr_table_set(wsreq->headers, "Upgrade", "websocket");
    apr_table_merge(wsreq->headers, "Connection", "Upgrade");
    /* TODO: add Sec-WebSocket-Key header */

    r = h2_create_request_rec(wsreq, c2, no_body);
    if (!r || r->status != HTTP_OK)
      goto leave;

    /* TODO: add output filter that checks response for:
     * - switching protocols
     * - a matching Sec-WebSocket-Accept header
     * - if ok, transform response to a 200
     * - if not, send failure response
     */

leave:
    return r;
}
