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
#include <apr_thread_cond.h>
#include <apr_atomic.h>
#include <apr_base64.h>
#include <apr_strings.h>

#include <ap_mpm.h>

#include <httpd.h>
#include <http_core.h>
#include <http_config.h>
#include <http_log.h>
#include <http_protocol.h>
#include <scoreboard.h>

#include <mpm_common.h>

#if APR_HAVE_UNISTD_H
#include <unistd.h>         /* for getpid() */
#endif

#include "h2_private.h"
#include "h2.h"
#include "h2_bucket_beam.h"
#include "h2_bucket_eos.h"
#include "h2_config.h"
#include "h2_conn_ctx.h"
#include "h2_protocol.h"
#include "h2_mplx.h"
#include "h2_push.h"
#include "h2_request.h"
#include "h2_headers.h"
#include "h2_stream.h"
#include "h2_c2.h"
#include "h2_session.h"
#include "h2_util.h"
#include "h2_version.h"
#include "h2_workers.h"


static void transit(h2_session *session, const char *action,
                    h2_session_state nstate);

static void on_stream_state_enter(void *ctx, h2_stream *stream);
static void on_stream_state_event(void *ctx, h2_stream *stream, h2_stream_event_t ev);
static void on_stream_event(void *ctx, h2_stream *stream, h2_stream_event_t ev);

static int h2_session_status_from_apr_status(apr_status_t rv)
{
    if (rv == APR_SUCCESS) {
        return NGHTTP2_NO_ERROR;
    }
    else if (APR_STATUS_IS_EAGAIN(rv)) {
        return NGHTTP2_ERR_WOULDBLOCK;
    }
    else if (APR_STATUS_IS_EOF(rv)) {
        return NGHTTP2_ERR_EOF;
    }
    return NGHTTP2_ERR_PROTO;
}

static h2_stream *get_stream(h2_session *session, int stream_id)
{
    return nghttp2_session_get_stream_user_data(session->ngh2, stream_id);
}

void h2_session_event(h2_session *session, h2_session_event_t ev,
                             int err, const char *msg)
{
    h2_session_dispatch_event(session, ev, err, msg);
}

static int rst_unprocessed_stream(h2_stream *stream, void *ctx)
{
    int unprocessed = (!h2_stream_is_at_or_past(stream, H2_SS_CLOSED)
                       && (H2_STREAM_CLIENT_INITIATED(stream->id)? 
                           (!stream->session->local.accepting
                            && stream->id > stream->session->local.accepted_max)
                            : 
                           (!stream->session->remote.accepting
                            && stream->id > stream->session->remote.accepted_max))
                       ); 
    if (unprocessed) {
        h2_stream_rst(stream, H2_ERR_NO_ERROR);
        return 0;
    }
    return 1;
}

static void cleanup_unprocessed_streams(h2_session *session)
{
    h2_mplx_c1_streams_do(session->mplx, rst_unprocessed_stream, session);
}

static h2_stream *h2_session_open_stream(h2_session *session, int stream_id,
                                         int initiated_on)
{
    h2_stream * stream;
    apr_pool_t *stream_pool;
    
    apr_pool_create(&stream_pool, session->pool);
    apr_pool_tag(stream_pool, "h2_stream");
    
    stream = h2_stream_create(stream_id, stream_pool, session, 
                              session->monitor, initiated_on);
    if (stream) {
        nghttp2_session_set_stream_user_data(session->ngh2, stream_id, stream);
    }
    return stream;
}

/**
 * Determine the priority order of streams.
 * - if both stream depend on the same one, compare weights
 * - if one stream is closer to the root, prioritize that one
 * - if both are on the same level, use the weight of their root
 *   level ancestors
 */
static int spri_cmp(int sid1, nghttp2_stream *s1, 
                    int sid2, nghttp2_stream *s2, h2_session *session)
{
    nghttp2_stream *p1, *p2;
    
    p1 = nghttp2_stream_get_parent(s1);
    p2 = nghttp2_stream_get_parent(s2);
    
    if (p1 == p2) {
        int32_t w1, w2;
        
        w1 = nghttp2_stream_get_weight(s1);
        w2 = nghttp2_stream_get_weight(s2);
        return w2 - w1;
    }
    else if (!p1) {
        /* stream 1 closer to root */
        return -1;
    }
    else if (!p2) {
        /* stream 2 closer to root */
        return 1;
    }
    return spri_cmp(sid1, p1, sid2, p2, session);
}

static int stream_pri_cmp(int sid1, int sid2, void *ctx)
{
    h2_session *session = ctx;
    nghttp2_stream *s1, *s2;
    
    s1 = nghttp2_session_find_stream(session->ngh2, sid1);
    s2 = nghttp2_session_find_stream(session->ngh2, sid2);

    if (s1 == s2) {
        return 0;
    }
    else if (!s1) {
        return 1;
    }
    else if (!s2) {
        return -1;
    }
    return spri_cmp(sid1, s1, sid2, s2, session);
}

/*
 * Callback when nghttp2 wants to send bytes back to the client.
 */
static ssize_t send_cb(nghttp2_session *ngh2,
                       const uint8_t *data, size_t length,
                       int flags, void *userp)
{
    h2_session *session = (h2_session *)userp;
    apr_status_t rv;
    (void)ngh2;
    (void)flags;

    if (h2_c1_io_needs_flush(&session->io)) {
        return NGHTTP2_ERR_WOULDBLOCK;
    }

    rv = h2_c1_io_add_data(&session->io, (const char *)data, length);
    if (APR_SUCCESS == rv) {
        return length;
    }
    else if (APR_STATUS_IS_EAGAIN(rv)) {
        return NGHTTP2_ERR_WOULDBLOCK;
    }
    else {
        ap_log_cerror(APLOG_MARK, APLOG_DEBUG, rv, session->c1,
                      APLOGNO(03062) "h2_session: send error");
        return h2_session_status_from_apr_status(rv);
    }
}

static int on_invalid_frame_recv_cb(nghttp2_session *ngh2,
                                    const nghttp2_frame *frame,
                                    int error, void *userp)
{
    h2_session *session = (h2_session *)userp;
    (void)ngh2;
    
    if (APLOGcdebug(session->c1)) {
        char buffer[256];
        
        h2_util_frame_print(frame, buffer, sizeof(buffer)/sizeof(buffer[0]));
        ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, session->c1,
                      H2_SSSN_LOG(APLOGNO(03063), session, 
                      "recv invalid FRAME[%s], frames=%ld/%ld (r/s)"),
                      buffer, (long)session->frames_received,
                     (long)session->frames_sent);
    }
    return 0;
}

static int on_data_chunk_recv_cb(nghttp2_session *ngh2, uint8_t flags,
                                 int32_t stream_id,
                                 const uint8_t *data, size_t len, void *userp)
{
    h2_session *session = (h2_session *)userp;
    apr_status_t status = APR_EINVAL;
    h2_stream * stream;
    int rv = 0;
    
    stream = get_stream(session, stream_id);
    if (stream) {
        ap_log_cerror(APLOG_MARK, APLOG_TRACE2, 0, session->c1,
                      H2_SSSN_STRM_MSG(session, stream_id, "write %ld bytes of DATA"),
                      (long)len);
        status = h2_stream_recv_DATA(stream, flags, data, len);
    }
    else {
        ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, session->c1, APLOGNO(03064)
                      H2_SSSN_STRM_MSG(session, stream_id,
                      "on_data_chunk for unknown stream"));
        rv = NGHTTP2_ERR_CALLBACK_FAILURE;
    }
    
    if (status != APR_SUCCESS) {
        /* count this as consumed explicitly as no one will read it */
        nghttp2_session_consume(session->ngh2, stream_id, len);
    }
    return rv;
}

static int on_stream_close_cb(nghttp2_session *ngh2, int32_t stream_id,
                              uint32_t error_code, void *userp)
{
    h2_session *session = (h2_session *)userp;
    h2_stream *stream;
    
    (void)ngh2;
    stream = get_stream(session, stream_id);
    if (stream) {
        if (error_code) {
            ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, session->c1,
                          H2_STRM_LOG(APLOGNO(03065), stream, 
                          "closing with err=%d %s"), 
                          (int)error_code, h2_protocol_err_description(error_code));
            h2_stream_rst(stream, error_code);
        }
    }
    return 0;
}

static int on_begin_headers_cb(nghttp2_session *ngh2,
                               const nghttp2_frame *frame, void *userp)
{
    h2_session *session = (h2_session *)userp;
    h2_stream *s = NULL;
    
    /* We may see HEADERs at the start of a stream or after all DATA
     * streams to carry trailers. */
    (void)ngh2;
    s = get_stream(session, frame->hd.stream_id);
    if (s) {
        /* nop */
    }
    else if (session->local.accepting) {
        s = h2_session_open_stream(userp, frame->hd.stream_id, 0);
    }
    return s? 0 : NGHTTP2_ERR_START_STREAM_NOT_ALLOWED;
}

static int on_header_cb(nghttp2_session *ngh2, const nghttp2_frame *frame,
                        const uint8_t *name, size_t namelen,
                        const uint8_t *value, size_t valuelen,
                        uint8_t flags,
                        void *userp)
{
    h2_session *session = (h2_session *)userp;
    h2_stream * stream;
    apr_status_t status;
    
    (void)flags;
    stream = get_stream(session, frame->hd.stream_id);
    if (!stream) {
        ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, session->c1, APLOGNO(02920)
                      H2_SSSN_STRM_MSG(session, frame->hd.stream_id,
                      "on_header unknown stream"));
        return NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE;
    }
    
    status = h2_stream_add_header(stream, (const char *)name, namelen,
                                  (const char *)value, valuelen);
    if (status != APR_SUCCESS &&
        (!stream->rtmp ||
         stream->rtmp->http_status == H2_HTTP_STATUS_UNSET ||
         /* We accept a certain amount of failures in order to reply
          * with an informative HTTP error response like 413. But of the
          * client is too wrong, we RESET the stream */
         stream->request_headers_failed > 100)) {
        ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, session->c1,
                      H2_SSSN_STRM_MSG(session, frame->hd.stream_id,
                      "RST stream, header failures: %d"),
                      (int)stream->request_headers_failed);
        return NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE;
    }
    return 0;
}

/**
 * nghttp2 session has received a complete frame. Most are used by nghttp2
 * for processing of internal state. Some, like HEADER and DATA frames,
 * we need to act on.
 */
static int on_frame_recv_cb(nghttp2_session *ng2s,
                            const nghttp2_frame *frame,
                            void *userp)
{
    h2_session *session = (h2_session *)userp;
    h2_stream *stream;
    apr_status_t rv = APR_SUCCESS;
    
    stream = frame->hd.stream_id? get_stream(session, frame->hd.stream_id) : NULL;
    if (APLOGcdebug(session->c1)) {
        char buffer[256];

        h2_util_frame_print(frame, buffer, sizeof(buffer)/sizeof(buffer[0]));
        if (stream) {
            ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, session->c1,
                          H2_STRM_LOG(APLOGNO(10302), stream,
                          "recv FRAME[%s], frames=%ld/%ld (r/s)"),
                          buffer, (long)session->frames_received,
                         (long)session->frames_sent);
        }
        else {
            ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, session->c1,
                          H2_SSSN_LOG(APLOGNO(03066), session,
                          "recv FRAME[%s], frames=%ld/%ld (r/s), "
                          "remote.emitted=%d"),
                          buffer, (long)session->frames_received,
                         (long)session->frames_sent,
                         (int)session->remote.emitted_count);
        }
    }

    ++session->frames_received;
    switch (frame->hd.type) {
        case NGHTTP2_HEADERS:
            /* This can be HEADERS for a new stream, defining the request,
             * or HEADER may come after DATA at the end of a stream as in
             * trailers */
            if (stream) {
                rv = h2_stream_recv_frame(stream, NGHTTP2_HEADERS, frame->hd.flags, 
                    frame->hd.length + H2_FRAME_HDR_LEN);
            }
            break;
        case NGHTTP2_DATA:
            if (stream) {
                ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, session->c1,
                              H2_STRM_LOG(APLOGNO(02923), stream, 
                              "DATA, len=%ld, flags=%d"), 
                              (long)frame->hd.length, frame->hd.flags);
                rv = h2_stream_recv_frame(stream, NGHTTP2_DATA, frame->hd.flags, 
                    frame->hd.length + H2_FRAME_HDR_LEN);
            }
            break;
        case NGHTTP2_PRIORITY:
            session->reprioritize = 1;
            ap_log_cerror(APLOG_MARK, APLOG_TRACE2, 0, session->c1,
                          H2_SSSN_STRM_MSG(session, frame->hd.stream_id, "PRIORITY frame "
                          " weight=%d, dependsOn=%d, exclusive=%d"),
                          frame->priority.pri_spec.weight,
                          frame->priority.pri_spec.stream_id,
                          frame->priority.pri_spec.exclusive);
            break;
        case NGHTTP2_WINDOW_UPDATE:
            ap_log_cerror(APLOG_MARK, APLOG_TRACE2, 0, session->c1,
                          H2_SSSN_STRM_MSG(session, frame->hd.stream_id,
                          "WINDOW_UPDATE incr=%d"),
                          frame->window_update.window_size_increment);
            break;
        case NGHTTP2_RST_STREAM:
            ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, session->c1, APLOGNO(03067)
                          H2_SSSN_STRM_MSG(session, frame->hd.stream_id,
                          "RST_STREAM by client, error=%d"),
                          (int)frame->rst_stream.error_code);
            if (stream) {
                rv = h2_stream_recv_frame(stream, NGHTTP2_RST_STREAM, frame->hd.flags,
                    frame->hd.length + H2_FRAME_HDR_LEN);
            }
            if (stream && stream->initiated_on) {
                /* A stream reset on a request we sent it. Normal, when the
                 * client does not want it. */
                ++session->pushes_reset;
            }
            else {
                /* A stream reset on a request it sent us. Could happen in a browser
                 * when the user navigates away or cancels loading - maybe. */
                h2_mplx_c1_client_rst(session->mplx, frame->hd.stream_id,
                                      stream);
            }
            ++session->streams_reset;
            break;
        case NGHTTP2_GOAWAY:
            if (frame->goaway.error_code == 0 
                && frame->goaway.last_stream_id == ((1u << 31) - 1)) {
                /* shutdown notice. Should not come from a client... */
                session->remote.accepting = 0;
            }
            else {
                session->remote.accepted_max = frame->goaway.last_stream_id;
                h2_session_dispatch_event(session, H2_SESSION_EV_REMOTE_GOAWAY,
                               frame->goaway.error_code, NULL);
            }
            break;
        case NGHTTP2_SETTINGS:
            ap_log_cerror(APLOG_MARK, APLOG_TRACE2, 0, session->c1,
                          H2_SSSN_MSG(session, "SETTINGS, len=%ld"), (long)frame->hd.length);
            break;
        default:
            if (APLOGctrace2(session->c1)) {
                char buffer[256];
                
                h2_util_frame_print(frame, buffer,
                                    sizeof(buffer)/sizeof(buffer[0]));
                ap_log_cerror(APLOG_MARK, APLOG_TRACE2, 0, session->c1,
                              H2_SSSN_MSG(session, "on_frame_rcv %s"), buffer);
            }
            break;
    }
    
    if (session->state == H2_SESSION_ST_IDLE) {
        /* We received a frame, but session is in state IDLE. That means the frame
         * did not really progress any of the (possibly) open streams. It was a meta
         * frame, e.g. SETTINGS/WINDOW_UPDATE/unknown/etc.
         * Remember: IDLE means we cannot send because either there are no streams open or
         * all open streams are blocked on exhausted WINDOWs for outgoing data.
         * The more frames we receive that do not change this, the less interested we
         * become in serving this connection. This is expressed in increasing "idle_delays".
         * Eventually, the connection will timeout and we'll close it. */
        session->idle_frames = H2MIN(session->idle_frames + 1, session->frames_received);
            ap_log_cerror( APLOG_MARK, APLOG_TRACE2, 0, session->c1,
                          H2_SSSN_MSG(session, "session has %ld idle frames"), 
                          (long)session->idle_frames);
        if (session->idle_frames > 10) {
            apr_size_t busy_frames = H2MAX(session->frames_received - session->idle_frames, 1);
            int idle_ratio = (int)(session->idle_frames / busy_frames); 
            if (idle_ratio > 100) {
                session->idle_delay = apr_time_from_msec(H2MIN(1000, idle_ratio));
            }
            else if (idle_ratio > 10) {
                session->idle_delay = apr_time_from_msec(10);
            }
            else if (idle_ratio > 1) {
                session->idle_delay = apr_time_from_msec(1);
            }
            else {
                session->idle_delay = 0;
            }
        }
    }
    
    if (APR_SUCCESS != rv) return NGHTTP2_ERR_PROTO;
    return 0;
}

static char immortal_zeros[H2_MAX_PADLEN];

static int on_send_data_cb(nghttp2_session *ngh2, 
                           nghttp2_frame *frame, 
                           const uint8_t *framehd, 
                           size_t length, 
                           nghttp2_data_source *source, 
                           void *userp)
{
    apr_status_t status = APR_SUCCESS;
    h2_session *session = (h2_session *)userp;
    int stream_id = (int)frame->hd.stream_id;
    unsigned char padlen;
    int eos;
    h2_stream *stream;
    apr_bucket *b;
    apr_off_t len = length;
    
    (void)ngh2;
    (void)source;
    ap_assert(frame->data.padlen <= (H2_MAX_PADLEN+1));
    padlen = (unsigned char)frame->data.padlen;
    
    stream = get_stream(session, stream_id);
    if (!stream) {
        ap_log_cerror(APLOG_MARK, APLOG_ERR, APR_NOTFOUND, session->c1,
                      APLOGNO(02924) 
                      H2_SSSN_STRM_MSG(session, stream_id, "send_data, stream not found"));
        return NGHTTP2_ERR_CALLBACK_FAILURE;
    }
    
    ap_log_cerror(APLOG_MARK, APLOG_TRACE2, 0, session->c1,
                  H2_STRM_MSG(stream, "send_data_cb for %ld bytes"),
                  (long)length);
                  
    status = h2_c1_io_add_data(&session->io, (const char *)framehd, H2_FRAME_HDR_LEN);
    if (padlen && status == APR_SUCCESS) {
        --padlen;
        status = h2_c1_io_add_data(&session->io, (const char *)&padlen, 1);
    }
    
    if (status != APR_SUCCESS) {
        ap_log_cerror(APLOG_MARK, APLOG_TRACE1, status, session->c1,
                      H2_STRM_MSG(stream, "writing frame header"));
        return NGHTTP2_ERR_CALLBACK_FAILURE;
    }
    
    status = h2_stream_read_to(stream, session->bbtmp, &len, &eos);
    if (status != APR_SUCCESS) {
        ap_log_cerror(APLOG_MARK, APLOG_TRACE1, status, session->c1,
                      H2_STRM_MSG(stream, "send_data_cb, reading stream"));
        apr_brigade_cleanup(session->bbtmp);
        return NGHTTP2_ERR_CALLBACK_FAILURE;
    }
    else if (len != (apr_off_t)length) {
        ap_log_cerror(APLOG_MARK, APLOG_TRACE1, status, session->c1,
                      H2_STRM_MSG(stream, "send_data_cb, wanted %ld bytes, "
                      "got %ld from stream"), (long)length, (long)len);
        apr_brigade_cleanup(session->bbtmp);
        return NGHTTP2_ERR_CALLBACK_FAILURE;
    }
    
    if (padlen) {
        b = apr_bucket_immortal_create(immortal_zeros, padlen, 
                                       session->c1->bucket_alloc);
        APR_BRIGADE_INSERT_TAIL(session->bbtmp, b);
    }
    
    status = h2_c1_io_append(&session->io, session->bbtmp);
    apr_brigade_cleanup(session->bbtmp);
    
    if (status == APR_SUCCESS) {
        stream->out_data_frames++;
        stream->out_data_octets += length;
        ap_log_cerror(APLOG_MARK, APLOG_TRACE2, 0, session->c1,
                      H2_STRM_MSG(stream, "sent data length=%ld, total=%ld"),
                      (long)length, (long)stream->out_data_octets);
        return 0;
    }
    else {
        ap_log_cerror(APLOG_MARK, APLOG_DEBUG, status, session->c1,
                      H2_STRM_LOG(APLOGNO(02925), stream, "failed send_data_cb"));
        return NGHTTP2_ERR_CALLBACK_FAILURE;
    }
}

static int on_frame_send_cb(nghttp2_session *ngh2, 
                            const nghttp2_frame *frame,
                            void *user_data)
{
    h2_session *session = user_data;
    h2_stream *stream;
    int stream_id = frame->hd.stream_id;
    
    ++session->frames_sent;
    switch (frame->hd.type) {
        case NGHTTP2_PUSH_PROMISE:
            /* PUSH_PROMISE we report on the promised stream */
            stream_id = frame->push_promise.promised_stream_id;
            break;
        default:    
            break;
    }
    
    stream = get_stream(session, stream_id);
    if (APLOGcdebug(session->c1)) {
        char buffer[256];
        
        h2_util_frame_print(frame, buffer, sizeof(buffer)/sizeof(buffer[0]));
        if (stream) {
            ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, session->c1,
                          H2_STRM_LOG(APLOGNO(10303), stream,
                          "sent FRAME[%s], frames=%ld/%ld (r/s)"),
                          buffer, (long)session->frames_received,
                         (long)session->frames_sent);
        }
        else {
            ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, session->c1,
                          H2_SSSN_LOG(APLOGNO(03068), session,
                          "sent FRAME[%s], frames=%ld/%ld (r/s)"),
                          buffer, (long)session->frames_received,
                         (long)session->frames_sent);
        }
    }
    
    if (stream) {
        h2_stream_send_frame(stream, frame->hd.type, frame->hd.flags, 
            frame->hd.length + H2_FRAME_HDR_LEN);
    }
    return 0;
}

#ifdef H2_NG2_INVALID_HEADER_CB
static int on_invalid_header_cb(nghttp2_session *ngh2,
                                const nghttp2_frame *frame, 
                                const uint8_t *name, size_t namelen, 
                                const uint8_t *value, size_t valuelen, 
                                uint8_t flags, void *user_data)
{
    h2_session *session = user_data;
    h2_stream *stream;
    
    ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, session->c1, APLOGNO(03456)
                  H2_SSSN_STRM_MSG(session, frame->hd.stream_id,
                  "invalid header '%.*s: %.*s'"),
                  (int)namelen, name, (int)valuelen, value);
    stream = get_stream(session, frame->hd.stream_id);
    if (stream) {
        h2_stream_rst(stream, NGHTTP2_PROTOCOL_ERROR);
    }
    return 0;
}
#endif

static ssize_t select_padding_cb(nghttp2_session *ngh2, 
                                 const nghttp2_frame *frame, 
                                 size_t max_payloadlen, void *user_data)
{
    h2_session *session = user_data;
    size_t frame_len = frame->hd.length + H2_FRAME_HDR_LEN; /* the total length without padding */
    size_t padded_len = frame_len;

    /* Determine # of padding bytes to append to frame. Unless session->padding_always
     * the number my be capped by the ui.write_size that currently applies. 
     */
    if (session->padding_max) {
        int n = ap_random_pick(0, session->padding_max);
        padded_len = H2MIN(max_payloadlen + H2_FRAME_HDR_LEN, frame_len + n); 
    }

    if (padded_len != frame_len) {
        if (!session->padding_always && session->io.write_size 
            && (padded_len > session->io.write_size)
            && (frame_len <= session->io.write_size)) {
            padded_len = session->io.write_size;
        }
        ap_log_cerror(APLOG_MARK, APLOG_TRACE2, 0, session->c1,
                      "select padding from [%d, %d]: %d (frame length: 0x%04x, write size: %d)",
                      (int)frame_len, (int)max_payloadlen+H2_FRAME_HDR_LEN,
                      (int)(padded_len - frame_len), (int)padded_len, (int)session->io.write_size);
        return padded_len - H2_FRAME_HDR_LEN;
    }
    return frame->hd.length;
}

#define NGH2_SET_CALLBACK(callbacks, name, fn)\
nghttp2_session_callbacks_set_##name##_callback(callbacks, fn)

static apr_status_t init_callbacks(conn_rec *c, nghttp2_session_callbacks **pcb)
{
    int rv = nghttp2_session_callbacks_new(pcb);
    if (rv != 0) {
        ap_log_cerror(APLOG_MARK, APLOG_ERR, 0, c,
                      APLOGNO(02926) "nghttp2_session_callbacks_new: %s",
                      nghttp2_strerror(rv));
        return APR_EGENERAL;
    }
    
    NGH2_SET_CALLBACK(*pcb, send, send_cb);
    NGH2_SET_CALLBACK(*pcb, on_frame_recv, on_frame_recv_cb);
    NGH2_SET_CALLBACK(*pcb, on_invalid_frame_recv, on_invalid_frame_recv_cb);
    NGH2_SET_CALLBACK(*pcb, on_data_chunk_recv, on_data_chunk_recv_cb);
    NGH2_SET_CALLBACK(*pcb, on_stream_close, on_stream_close_cb);
    NGH2_SET_CALLBACK(*pcb, on_begin_headers, on_begin_headers_cb);
    NGH2_SET_CALLBACK(*pcb, on_header, on_header_cb);
    NGH2_SET_CALLBACK(*pcb, send_data, on_send_data_cb);
    NGH2_SET_CALLBACK(*pcb, on_frame_send, on_frame_send_cb);
#ifdef H2_NG2_INVALID_HEADER_CB
    NGH2_SET_CALLBACK(*pcb, on_invalid_header, on_invalid_header_cb);
#endif
    NGH2_SET_CALLBACK(*pcb, select_padding, select_padding_cb);
    return APR_SUCCESS;
}

static void update_child_status(h2_session *session, int status,
                                const char *msg, const h2_stream *stream)
{
    /* Assume that we also change code/msg when something really happened and
     * avoid updating the scoreboard in between */
    if (session->last_status_code != status
        || session->last_status_msg != msg) {
        char sbuffer[1024];
        sbuffer[0] = '\0';
        if (stream) {
            apr_snprintf(sbuffer, sizeof(sbuffer),
                         ": stream %d, %s %s",
                         stream->id,
                         stream->request? stream->request->method : "",
                         stream->request? stream->request->path : "");
        }
        apr_snprintf(session->status, sizeof(session->status),
                     "[%d/%d] %s%s",
                     (int)(session->remote.emitted_count + session->pushes_submitted),
                     (int)session->streams_done,
                     msg? msg : "-", sbuffer);
        ap_update_child_status_from_server(session->c1->sbh, status,
                                           session->c1, session->s);
        ap_update_child_status_descr(session->c1->sbh, status, session->status);
    }
}

static apr_status_t h2_session_shutdown_notice(h2_session *session)
{
    apr_status_t status;
    
    ap_assert(session);
    if (!session->local.accepting) {
        return APR_SUCCESS;
    }
    
    nghttp2_submit_shutdown_notice(session->ngh2);
    session->local.accepting = 0;
    status = nghttp2_session_send(session->ngh2);
    if (status == APR_SUCCESS) {
        status = h2_c1_io_assure_flushed(&session->io);
    }
    ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, session->c1,
                  H2_SSSN_LOG(APLOGNO(03457), session, "sent shutdown notice"));
    return status;
}

static apr_status_t h2_session_shutdown(h2_session *session, int error, 
                                        const char *msg, int force_close)
{
    apr_status_t status = APR_SUCCESS;
    
    ap_assert(session);
    if (session->local.shutdown) {
        return APR_SUCCESS;
    }

    if (error && !msg) {
        if (APR_STATUS_IS_EPIPE(error)) {
            msg = "remote close";
        }
    }

    if (error || force_close) {
        /* not a graceful shutdown, we want to leave... 
         * Do not start further streams that are waiting to be scheduled. 
         * Find out the max stream id that we habe been processed or
         * are still actively working on.
         * Remove all streams greater than this number without submitting
         * a RST_STREAM frame, since that should be clear from the GOAWAY
         * we send. */
        session->local.accepted_max = h2_mplx_c1_shutdown(session->mplx);
        session->local.error = error;
        session->local.error_msg = msg;
    }
    else {
        /* graceful shutdown. we will continue processing all streams
         * we have, but no longer accept new ones. Report the max stream
         * we have received and discard all new ones. */
    }
    
    session->local.accepting = 0;
    session->local.shutdown = 1;
    if (!session->c1->aborted) {
        nghttp2_submit_goaway(session->ngh2, NGHTTP2_FLAG_NONE, 
                              session->local.accepted_max, 
                              error, (uint8_t*)msg, msg? strlen(msg):0);
        status = nghttp2_session_send(session->ngh2);
        if (status == APR_SUCCESS) {
            status = h2_c1_io_assure_flushed(&session->io);
        }
        ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, session->c1,
                      H2_SSSN_LOG(APLOGNO(03069), session, 
                                  "sent GOAWAY, err=%d, msg=%s"), error, msg? msg : "");
    }
    h2_session_dispatch_event(session, H2_SESSION_EV_LOCAL_GOAWAY, error, msg);
    return status;
}

static apr_status_t session_cleanup(h2_session *session, const char *trigger)
{
    conn_rec *c = session->c1;
    ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, c,
                  H2_SSSN_MSG(session, "pool_cleanup"));
    
    if (session->state != H2_SESSION_ST_DONE
        && session->state != H2_SESSION_ST_INIT) {
        /* Not good. The connection is being torn down and we have
         * not sent a goaway. This is considered a protocol error and
         * the client has to assume that any streams "in flight" may have
         * been processed and are not safe to retry.
         * As clients with idle connection may only learn about a closed
         * connection when sending the next request, this has the effect
         * that at least this one request will fail.
         */
        ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, c,
                      H2_SSSN_LOG(APLOGNO(03199), session, 
                      "connection disappeared without proper "
                      "goodbye, clients will be confused, should not happen"));
    }

    if (!h2_iq_empty(session->ready_to_process)) {
        int sid;
        ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, c,
                      H2_SSSN_LOG(APLOGNO(10485), session,
                      "cleanup, resetting %d streams in ready-to-process"),
                      h2_iq_count(session->ready_to_process));
        while ((sid = h2_iq_shift(session->ready_to_process)) > 0) {
          h2_mplx_c1_client_rst(session->mplx, sid, get_stream(session, sid));
        }
    }

    transit(session, trigger, H2_SESSION_ST_CLEANUP);
    h2_mplx_c1_destroy(session->mplx);
    session->mplx = NULL;

    ap_assert(session->ngh2);
    nghttp2_session_del(session->ngh2);
    session->ngh2 = NULL;
    h2_conn_ctx_detach(c);

    return APR_SUCCESS;
}

static apr_status_t session_pool_cleanup(void *data)
{
    conn_rec *c = data;
    h2_conn_ctx_t *conn_ctx = h2_conn_ctx_get(c);
    h2_session *session = conn_ctx? conn_ctx->session : NULL;

    if (session) {
        int mpm_state = 0;
        int level;

        ap_mpm_query(AP_MPMQ_MPM_STATE, &mpm_state);
        level = (AP_MPMQ_STOPPING == mpm_state)? APLOG_DEBUG : APLOG_WARNING;
        /* if the session is still there, now is the last chance
         * to perform cleanup. Normally, cleanup should have happened
         * earlier in the connection pre_close.
         * However, when the server is stopping, it may shutdown connections
         * without running the pre_close hooks. Do not want about that. */
        ap_log_cerror(APLOG_MARK, level, 0, c,
                      H2_SSSN_LOG(APLOGNO(10020), session,
                      "session cleanup triggered by pool cleanup. "
                      "this should have happened earlier already."));
        return session_cleanup(session, "pool cleanup");
    }
    return APR_SUCCESS;
}

static /* atomic */ apr_uint32_t next_id;

apr_status_t h2_session_create(h2_session **psession, conn_rec *c, request_rec *r,
                               server_rec *s, h2_workers *workers)
{
    nghttp2_session_callbacks *callbacks = NULL;
    nghttp2_option *options = NULL;
    uint32_t n;
    int thread_num;
    apr_pool_t *pool = NULL;
    h2_session *session;
    h2_stream *stream0;
    apr_status_t status;
    int rv;

    *psession = NULL;
    apr_pool_create(&pool, c->pool);
    apr_pool_tag(pool, "h2_session");
    session = apr_pcalloc(pool, sizeof(h2_session));
    if (!session) {
        return APR_ENOMEM;
    }
    
    *psession = session;
    /* c->id does not give a unique id for the lifetime of the session.
     * mpms like event change c->id when re-activating a keepalive
     * connection based on the child_num+thread_num of the worker
     * processing it.
     * We'd like to have an id that remains constant and unique bc
     * h2 streams can live through keepalive periods. While double id
     * will not lead to processing failures, it will confuse log analysis.
     */
#if AP_MODULE_MAGIC_AT_LEAST(20211221, 8)
    ap_sb_get_child_thread(c->sbh, &session->child_num, &thread_num);
#else
    (void)thread_num;
    session->child_num = (int)getpid();
#endif
    session->id = apr_atomic_inc32(&next_id);
    session->c1 = c;
    session->r = r;
    session->s = s;
    session->pool = pool;
    session->workers = workers;
    
    session->state = H2_SESSION_ST_INIT;
    session->local.accepting = 1;
    session->remote.accepting = 1;
    
    session->max_stream_count = h2_config_sgeti(s, H2_CONF_MAX_STREAMS);
    session->max_stream_mem = h2_config_sgeti(s, H2_CONF_STREAM_MAX_MEM);
    session->max_data_frame_len = h2_config_sgeti(s, H2_CONF_MAX_DATA_FRAME_LEN);

    session->out_c1_blocked = h2_iq_create(session->pool, (int)session->max_stream_count);
    session->ready_to_process = h2_iq_create(session->pool, (int)session->max_stream_count);

    session->monitor = apr_pcalloc(pool, sizeof(h2_stream_monitor));
    session->monitor->ctx = session;
    session->monitor->on_state_enter = on_stream_state_enter;
    session->monitor->on_state_event = on_stream_state_event;
    session->monitor->on_event = on_stream_event;

    stream0 = h2_stream_create(0, session->pool, session, NULL, 0);
    stream0->c2 = session->c1;  /* stream0's connection is the main connection */
    session->mplx = h2_mplx_c1_create(session->child_num, session->id,
                                      stream0, s, session->pool, workers);
    if (!session->mplx) {
        apr_pool_destroy(pool);
        return APR_ENOTIMPL;
    }

    h2_c1_io_init(&session->io, session);
    session->padding_max = h2_config_sgeti(s, H2_CONF_PADDING_BITS);
    if (session->padding_max) {
        session->padding_max = (0x01 << session->padding_max) - 1; 
    }
    session->padding_always = h2_config_sgeti(s, H2_CONF_PADDING_ALWAYS);
    session->bbtmp = apr_brigade_create(session->pool, c->bucket_alloc);
    
    status = init_callbacks(c, &callbacks);
    if (status != APR_SUCCESS) {
        ap_log_cerror(APLOG_MARK, APLOG_ERR, status, c, APLOGNO(02927) 
                      "nghttp2: error in init_callbacks");
        apr_pool_destroy(pool);
        return status;
    }
    
    rv = nghttp2_option_new(&options);
    if (rv != 0) {
        ap_log_cerror(APLOG_MARK, APLOG_ERR, APR_EGENERAL, c,
                      APLOGNO(02928) "nghttp2_option_new: %s", 
                      nghttp2_strerror(rv));
        apr_pool_destroy(pool);
        return status;
    }
    nghttp2_option_set_peer_max_concurrent_streams(options, (uint32_t)session->max_stream_count);
    /* We need to handle window updates ourself, otherwise we
     * get flooded by nghttp2. */
    nghttp2_option_set_no_auto_window_update(options, 1);
#ifdef H2_NG2_NO_CLOSED_STREAMS
    /* We do not want nghttp2 to keep information about closed streams as
     * that accumulates memory on long connections. This makes PRIORITY
     * setting in relation to older streams non-working. */
    nghttp2_option_set_no_closed_streams(options, 1);
#endif
#ifdef H2_NG2_RFC9113_STRICTNESS
    /* nghttp2 v1.50.0 introduces the strictness checks on leading/trailing
     * whitespace of RFC 9113 for fields. But, by default, it RST streams
     * carrying such. We do not want that. We want to strip the ws and
     * handle them, just like the HTTP/1.1 parser does. */
    nghttp2_option_set_no_rfc9113_leading_and_trailing_ws_validation(options, 1);
#endif
    rv = nghttp2_session_server_new2(&session->ngh2, callbacks,
                                     session, options);
    nghttp2_session_callbacks_del(callbacks);
    nghttp2_option_del(options);
    
    if (rv != 0) {
        ap_log_cerror(APLOG_MARK, APLOG_ERR, APR_EGENERAL, c,
                      APLOGNO(02929) "nghttp2_session_server_new: %s",
                      nghttp2_strerror(rv));
        apr_pool_destroy(pool);
        return APR_ENOMEM;
    }
    
    n = h2_config_sgeti(s, H2_CONF_PUSH_DIARY_SIZE);
    session->push_diary = h2_push_diary_create(session->pool, n);
    
    if (APLOGcdebug(c)) {
        ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, c, 
                      H2_SSSN_LOG(APLOGNO(03200), session, 
                                  "created, max_streams=%d, stream_mem=%d, "
                                  "workers_limit=%d, workers_max=%d, "
                                  "push_diary(type=%d,N=%d), "
                                  "max_data_frame_len=%d"),
                      (int)session->max_stream_count, 
                      (int)session->max_stream_mem,
                      session->mplx->processing_limit,
                      session->mplx->processing_max,
                      session->push_diary->dtype, 
                      (int)session->push_diary->N,
                      (int)session->max_data_frame_len);
    }
    
    apr_pool_pre_cleanup_register(pool, c, session_pool_cleanup);
        
    return APR_SUCCESS;
}

static apr_status_t h2_session_start(h2_session *session, int *rv)
{
    apr_status_t status = APR_SUCCESS;
    nghttp2_settings_entry settings[4];
    size_t slen;
    int win_size;
    
    ap_assert(session);
    /* Start the conversation by submitting our SETTINGS frame */
    *rv = 0;
    if (session->r) {
        const char *s, *cs;
        apr_size_t dlen; 
        h2_stream * stream;

        /* 'h2c' mode: we should have a 'HTTP2-Settings' header with
         * base64 encoded client settings. */
        s = apr_table_get(session->r->headers_in, "HTTP2-Settings");
        if (!s) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, APR_EINVAL, session->r,
                          APLOGNO(02931) 
                          "HTTP2-Settings header missing in request");
            return APR_EINVAL;
        }
        cs = NULL;
        dlen = h2_util_base64url_decode(&cs, s, session->pool);
        
        if (APLOGrdebug(session->r)) {
            char buffer[128];
            h2_util_hex_dump(buffer, 128, (char*)cs, dlen);
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, session->r, APLOGNO(03070)
                          "upgrading h2c session with HTTP2-Settings: %s -> %s (%d)",
                          s, buffer, (int)dlen);
        }
        
        *rv = nghttp2_session_upgrade(session->ngh2, (uint8_t*)cs, dlen, NULL);
        if (*rv != 0) {
            status = APR_EINVAL;
            ap_log_rerror(APLOG_MARK, APLOG_ERR, status, session->r,
                          APLOGNO(02932) "nghttp2_session_upgrade: %s", 
                          nghttp2_strerror(*rv));
            return status;
        }
        
        /* Now we need to auto-open stream 1 for the request we got. */
        stream = h2_session_open_stream(session, 1, 0);
        if (!stream) {
            status = APR_EGENERAL;
            ap_log_rerror(APLOG_MARK, APLOG_ERR, status, session->r,
                          APLOGNO(02933) "open stream 1: %s", 
                          nghttp2_strerror(*rv));
            return status;
        }
        
        status = h2_stream_set_request_rec(stream, session->r, 1);
        if (status != APR_SUCCESS) {
            return status;
        }
    }

    slen = 0;
    settings[slen].settings_id = NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS;
    settings[slen].value = (uint32_t)session->max_stream_count;
    ++slen;
    win_size = h2_config_sgeti(session->s, H2_CONF_WIN_SIZE);
    if (win_size != H2_INITIAL_WINDOW_SIZE) {
        settings[slen].settings_id = NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE;
        settings[slen].value = win_size;
        ++slen;
    }
#if H2_USE_WEBSOCKETS
    if (h2_config_sgeti(session->s, H2_CONF_WEBSOCKETS)) {
      settings[slen].settings_id = NGHTTP2_SETTINGS_ENABLE_CONNECT_PROTOCOL;
      settings[slen].value = 1;
      ++slen;
    }
#endif

    ap_log_cerror(APLOG_MARK, APLOG_DEBUG, status, session->c1,
                  H2_SSSN_LOG(APLOGNO(03201), session, 
                  "start, INITIAL_WINDOW_SIZE=%ld, MAX_CONCURRENT_STREAMS=%d"), 
                  (long)win_size, (int)session->max_stream_count);
    *rv = nghttp2_submit_settings(session->ngh2, NGHTTP2_FLAG_NONE,
                                  settings, slen);
    if (*rv != 0) {
        status = APR_EGENERAL;
        ap_log_cerror(APLOG_MARK, APLOG_ERR, status, session->c1,
                      H2_SSSN_LOG(APLOGNO(02935), session, 
                      "nghttp2_submit_settings: %s"), nghttp2_strerror(*rv));
    }
    else {
        /* use maximum possible value for connection window size. We are only
         * interested in per stream flow control. which have the initial window
         * size configured above.
         * Therefore, for our use, the connection window can only get in the
         * way. Example: if we allow 100 streams with a 32KB window each, we
         * buffer up to 3.2 MB of data. Unless we do separate connection window
         * interim updates, any smaller connection window will lead to blocking
         * in DATA flow.
         */
        *rv = nghttp2_submit_window_update(session->ngh2, NGHTTP2_FLAG_NONE,
                                           0, NGHTTP2_MAX_WINDOW_SIZE - win_size);
        if (*rv != 0) {
            status = APR_EGENERAL;
            ap_log_cerror(APLOG_MARK, APLOG_ERR, status, session->c1,
                          H2_SSSN_LOG(APLOGNO(02970), session,
                          "nghttp2_submit_window_update: %s"), 
                          nghttp2_strerror(*rv));        
        }
    }
    
    return status;
}

struct h2_stream *h2_session_push(h2_session *session, h2_stream *is,
                                  h2_push *push)
{
    h2_stream *stream;
    h2_ngheader *ngh;
    apr_status_t status;
    int nid = 0;
    
    status = h2_req_create_ngheader(&ngh, is->pool, push->req);
    if (status == APR_SUCCESS) {
        nid = nghttp2_submit_push_promise(session->ngh2, 0, is->id, 
                                          ngh->nv, ngh->nvlen, NULL);
    }
    if (status != APR_SUCCESS || nid <= 0) {
        ap_log_cerror(APLOG_MARK, APLOG_DEBUG, status, session->c1,
                      H2_STRM_LOG(APLOGNO(03075), is, 
                      "submitting push promise fail: %s"), nghttp2_strerror(nid));
        return NULL;
    }
    ++session->pushes_promised;
    
    ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, session->c1,
                  H2_STRM_LOG(APLOGNO(03076), is, "SERVER_PUSH %d for %s %s on %d"),
                  nid, push->req->method, push->req->path, is->id);
                  
    stream = h2_session_open_stream(session, nid, is->id);
    if (!stream) {
        ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, session->c1,
                      H2_STRM_LOG(APLOGNO(03077), is,
                      "failed to create stream obj %d"), nid);
        /* kill the push_promise */
        nghttp2_submit_rst_stream(session->ngh2, NGHTTP2_FLAG_NONE, nid,
                                  NGHTTP2_INTERNAL_ERROR);
        return NULL;
    }
    
    h2_session_set_prio(session, stream, push->priority);
    h2_stream_set_request(stream, push->req);
    return stream;
}

static int valid_weight(float f) 
{
    int w = (int)f;
    return (w < NGHTTP2_MIN_WEIGHT? NGHTTP2_MIN_WEIGHT : 
            (w > NGHTTP2_MAX_WEIGHT)? NGHTTP2_MAX_WEIGHT : w);
}

apr_status_t h2_session_set_prio(h2_session *session, h2_stream *stream, 
                                 const h2_priority *prio)
{
    apr_status_t status = APR_SUCCESS;
    nghttp2_stream *s_grandpa, *s_parent, *s;
    
    if (prio == NULL) {
        /* we treat this as a NOP */
        return APR_SUCCESS;
    }
    s = nghttp2_session_find_stream(session->ngh2, stream->id);
    if (!s) {
        ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, session->c1,
                      H2_STRM_MSG(stream, "lookup of nghttp2_stream failed"));
        return APR_EINVAL;
    }
    
    s_parent = nghttp2_stream_get_parent(s);
    if (s_parent) {
        nghttp2_priority_spec ps;
        int id_parent, id_grandpa, w_parent, w;
        int rv = 0;
        const char *ptype = "AFTER";
        h2_dependency dep = prio->dependency;
        
        id_parent = nghttp2_stream_get_stream_id(s_parent);
        s_grandpa = nghttp2_stream_get_parent(s_parent);
        if (s_grandpa) {
            id_grandpa = nghttp2_stream_get_stream_id(s_grandpa);
        }
        else {
            /* parent of parent does not exist, 
             * only possible if parent == root */
            dep = H2_DEPENDANT_AFTER;
        }
        
        switch (dep) {
            case H2_DEPENDANT_INTERLEAVED:
                /* PUSHed stream is to be interleaved with initiating stream.
                 * It is made a sibling of the initiating stream and gets a
                 * proportional weight [1, MAX_WEIGHT] of the initiaing
                 * stream weight.
                 */
                ptype = "INTERLEAVED";
                w_parent = nghttp2_stream_get_weight(s_parent);
                w = valid_weight(w_parent * ((float)prio->weight / NGHTTP2_MAX_WEIGHT));
                nghttp2_priority_spec_init(&ps, id_grandpa, w, 0);
                break;
                
            case H2_DEPENDANT_BEFORE:
                /* PUSHed stream os to be sent BEFORE the initiating stream.
                 * It gets the same weight as the initiating stream, replaces
                 * that stream in the dependency tree and has the initiating
                 * stream as child.
                 */
                ptype = "BEFORE";
                w = w_parent = nghttp2_stream_get_weight(s_parent);
                nghttp2_priority_spec_init(&ps, stream->id, w_parent, 0);
                id_grandpa = nghttp2_stream_get_stream_id(s_grandpa);
                rv = nghttp2_session_change_stream_priority(session->ngh2, id_parent, &ps);
                if (rv < 0) {
                    ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, session->c1, APLOGNO(03202)
                                  H2_SSSN_STRM_MSG(session, id_parent,
                                  "PUSH BEFORE, weight=%d, depends=%d, returned=%d"),
                                  ps.weight, ps.stream_id, rv);
                    return APR_EGENERAL;
                }
                nghttp2_priority_spec_init(&ps, id_grandpa, w, 0);
                break;
                
            case H2_DEPENDANT_AFTER:
                /* The PUSHed stream is to be sent after the initiating stream.
                 * Give if the specified weight and let it depend on the intiating
                 * stream.
                 */
                /* fall through, it's the default */
            default:
                nghttp2_priority_spec_init(&ps, id_parent, valid_weight(prio->weight), 0);
                break;
        }


        rv = nghttp2_session_change_stream_priority(session->ngh2, stream->id, &ps);
        ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, session->c1,
                      H2_STRM_LOG(APLOGNO(03203), stream, 
                      "PUSH %s, weight=%d, depends=%d, returned=%d"),
                      ptype, ps.weight, ps.stream_id, rv);
        status = (rv < 0)? APR_EGENERAL : APR_SUCCESS;
    }

    return status;
}

int h2_session_push_enabled(h2_session *session)
{
    /* iff we can and they can and want */
    return (session->remote.accepting /* remote GOAWAY received */
            && h2_config_sgeti(session->s, H2_CONF_PUSH)
            && nghttp2_session_get_remote_settings(session->ngh2, 
                   NGHTTP2_SETTINGS_ENABLE_PUSH));
}

static int h2_session_want_send(h2_session *session)
{
    return nghttp2_session_want_write(session->ngh2)
        || h2_c1_io_pending(&session->io);
}

static apr_status_t h2_session_send(h2_session *session)
{
    int ngrv, pending = 0;
    apr_status_t rv = APR_SUCCESS;

    while (nghttp2_session_want_write(session->ngh2)) {
        ngrv = nghttp2_session_send(session->ngh2);
        ap_log_cerror(APLOG_MARK, APLOG_TRACE2, 0, session->c1,
                      "nghttp2_session_send: %d", (int)ngrv);
        pending = 1;
        if (ngrv != 0 && ngrv != NGHTTP2_ERR_WOULDBLOCK) {
            if (nghttp2_is_fatal(ngrv)) {
                h2_session_dispatch_event(session, H2_SESSION_EV_PROTO_ERROR,
                               ngrv, nghttp2_strerror(ngrv));
                rv = APR_EGENERAL;
                goto cleanup;
            }
        }
        if (h2_c1_io_needs_flush(&session->io) ||
            ngrv == NGHTTP2_ERR_WOULDBLOCK) {
            rv = h2_c1_io_assure_flushed(&session->io);
            if (rv != APR_SUCCESS)
                goto cleanup;
            pending = 0;
        }
    }
    if (pending) {
        rv = h2_c1_io_pass(&session->io);
    }
cleanup:
    if (rv != APR_SUCCESS) {
        h2_session_dispatch_event(session, H2_SESSION_EV_CONN_ERROR, rv, NULL);
    }
    return rv;
}

/**
 * A streams input state has changed.
 */
static void on_stream_input(void *ctx, h2_stream *stream)
{
    h2_session *session = ctx;

    ap_assert(stream);
    ap_log_cerror(APLOG_MARK, APLOG_TRACE2, 0, session->c1,
                  H2_STRM_MSG(stream, "on_input change"));
    update_child_status(session, SERVER_BUSY_READ, "read", stream);
    if (stream->id == 0) {
        /* input on primary connection available? read */
        h2_c1_read(session);
    }
    else {
        h2_stream_on_input_change(stream);
    }
}

/**
 * A streams output state has changed.
 */
static void on_stream_output(void *ctx, h2_stream *stream)
{
    h2_session *session = ctx;

    ap_assert(stream);
    ap_log_cerror(APLOG_MARK, APLOG_TRACE2, 0, session->c1,
                  H2_STRM_MSG(stream, "on_output change"));
    if (stream->id != 0) {
        update_child_status(session, SERVER_BUSY_WRITE, "write", stream);
        h2_stream_on_output_change(stream);
    }
}


static const char *StateNames[] = {
    "INIT",      /* H2_SESSION_ST_INIT */
    "DONE",      /* H2_SESSION_ST_DONE */
    "IDLE",      /* H2_SESSION_ST_IDLE */
    "BUSY",      /* H2_SESSION_ST_BUSY */
    "WAIT",      /* H2_SESSION_ST_WAIT */
    "CLEANUP",   /* H2_SESSION_ST_CLEANUP */
};

const char *h2_session_state_str(h2_session_state state)
{
    if (state >= (sizeof(StateNames)/sizeof(StateNames[0]))) {
        return "unknown";
    }
    return StateNames[state];
}

static void transit(h2_session *session, const char *action, h2_session_state nstate)
{
    int ostate;

    if (session->state != nstate) {
        ostate = session->state;

        ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, session->c1,
                      H2_SSSN_LOG(APLOGNO(03078), session, 
                      "transit [%s] -- %s --> [%s]"), 
                      h2_session_state_str(ostate), action, 
                      h2_session_state_str(nstate));
        
        switch (session->state) {
            case H2_SESSION_ST_IDLE:
                if (!session->remote.emitted_count) {
                    /* on fresh connections, with async mpm, do not return
                     * to mpm for a second. This gives the first request a better
                     * chance to arrive (und connection leaving IDLE state).
                     * If we return to mpm right away, this connection has the
                     * same chance of being cleaned up by the mpm as connections
                     * that already served requests - not fair. */
                    ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, session->c1,
                                  H2_SSSN_LOG("", session, "enter idle"));
                }
                else {
                    /* normal keepalive setup */
                    ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, session->c1,
                                  H2_SSSN_LOG("", session, "enter keepalive"));
                }
                session->state = nstate;
                break;
            case H2_SESSION_ST_DONE:
                break;
            default:
                /* nop */
                session->state = nstate;
                break;
        }
    }
}

static void h2_session_ev_init(h2_session *session, int arg, const char *msg)
{
    switch (session->state) {
        case H2_SESSION_ST_INIT:
            transit(session, "init", H2_SESSION_ST_BUSY);
            break;
        default:
            /* nop */
            break;
    }
}

static void h2_session_ev_input_pending(h2_session *session, int arg, const char *msg)
{
    switch (session->state) {
        case H2_SESSION_ST_INIT:
        case H2_SESSION_ST_IDLE:
        case H2_SESSION_ST_WAIT:
            transit(session, "input read", H2_SESSION_ST_BUSY);
            break;
        default:
            break;
    }
}

static void h2_session_ev_input_exhausted(h2_session *session, int arg, const char *msg)
{
    switch (session->state) {
        case H2_SESSION_ST_BUSY:
            if (!h2_session_want_send(session)) {
                if (session->open_streams == 0) {
                    transit(session, "input exhausted, no streams", H2_SESSION_ST_IDLE);
                }
                else {
                    transit(session, "input exhausted", H2_SESSION_ST_WAIT);
                }
            }
            break;
        case H2_SESSION_ST_WAIT:
            if (session->open_streams == 0) {
                transit(session, "input exhausted, no streams", H2_SESSION_ST_IDLE);
            }
            break;
        default:
            break;
    }
}

static void h2_session_ev_local_goaway(h2_session *session, int arg, const char *msg)
{
    cleanup_unprocessed_streams(session);
    transit(session, "local goaway", H2_SESSION_ST_DONE);
}

static void h2_session_ev_remote_goaway(h2_session *session, int arg, const char *msg)
{
    if (!session->remote.shutdown) {
        session->remote.error = arg;
        session->remote.accepting = 0;
        session->remote.shutdown = 1;
        cleanup_unprocessed_streams(session);
        transit(session, "remote goaway", H2_SESSION_ST_DONE);
    }
}

static void h2_session_ev_conn_error(h2_session *session, int arg, const char *msg)
{
    switch (session->state) {
        case H2_SESSION_ST_INIT:
        case H2_SESSION_ST_DONE:
            /* just leave */
            transit(session, "conn error", H2_SESSION_ST_DONE);
            break;
        
        default:
            ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, session->c1,
                          H2_SSSN_LOG(APLOGNO(03401), session, 
                          "conn error -> shutdown, remote.emitted=%d"),
                          (int)session->remote.emitted_count);
            h2_session_shutdown(session, arg, msg, 0);
            break;
    }
}

static void h2_session_ev_proto_error(h2_session *session, int arg, const char *msg)
{
    if (!session->local.shutdown) {
        ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, session->c1,
                      H2_SSSN_LOG(APLOGNO(03402), session, 
                      "proto error -> shutdown"));
        h2_session_shutdown(session, arg, msg, 0);
    }
}

static void h2_session_ev_conn_timeout(h2_session *session, int arg, const char *msg)
{
    transit(session, msg, H2_SESSION_ST_DONE);
    if (!session->local.shutdown) {
        h2_session_shutdown(session, arg, msg, 1);
    }
}

static void h2_session_ev_ngh2_done(h2_session *session, int arg, const char *msg)
{
    switch (session->state) {
        case H2_SESSION_ST_DONE:
            /* nop */
            break;
        default:
            transit(session, "nghttp2 done", H2_SESSION_ST_DONE);
            break;
    }
}

static void h2_session_ev_mpm_stopping(h2_session *session, int arg, const char *msg)
{
    switch (session->state) {
        case H2_SESSION_ST_DONE:
            /* nop */
            break;
        default:
            h2_session_shutdown_notice(session);
#if !AP_MODULE_MAGIC_AT_LEAST(20120211, 110)
            h2_workers_graceful_shutdown(session->workers);
#endif
            break;
    }
}

static void h2_session_ev_pre_close(h2_session *session, int arg, const char *msg)
{
    h2_session_shutdown(session, arg, msg, 1);
}

static void h2_session_ev_no_more_streams(h2_session *session)
{
    ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, session->c1,
                  H2_SSSN_LOG(APLOGNO(10304), session, "no more streams"));
    switch (session->state) {
        case H2_SESSION_ST_BUSY:
        case H2_SESSION_ST_WAIT:
            if (!h2_session_want_send(session)) {
                if (session->local.accepting) {
                    /* We wait for new frames on c1 only. */
                    transit(session, "all streams done", H2_SESSION_ST_IDLE);
                }
                else {
                    /* We are no longer accepting new streams.
                     * Time to leave. */
                    h2_session_shutdown(session, 0, "done", 0);
                    transit(session, "c1 done after goaway", H2_SESSION_ST_DONE);
                }
            }
            else {
                transit(session, "no more streams", H2_SESSION_ST_WAIT);
            }
            break;
        default:
            /* nop */
            break;
    }
}

static void ev_stream_created(h2_session *session, h2_stream *stream)
{
    /* nop */
}

static void ev_stream_open(h2_session *session, h2_stream *stream)
{
    if (H2_STREAM_CLIENT_INITIATED(stream->id)) {
        if (stream->id > session->remote.accepted_max) {
            session->local.accepted_max = stream->id;
        }
    }
    else {
        if (stream->id > session->local.emitted_max) {
            ++session->local.emitted_count;
            session->remote.emitted_max = stream->id;
        }
    }
    /* Stream state OPEN means we have received all request headers
     * and can start processing the stream. */
    h2_iq_append(session->ready_to_process, stream->id);
    update_child_status(session, SERVER_BUSY_READ, "schedule", stream);
}

static void ev_stream_closed(h2_session *session, h2_stream *stream)
{
    apr_bucket *b;
    
    if (H2_STREAM_CLIENT_INITIATED(stream->id)
        && (stream->id > session->local.completed_max)) {
        session->local.completed_max = stream->id;
    }
    /* The stream might have data in the buffers of the main connection.
     * We can only free the allocated resources once all had been written.
     * Send a special buckets on the connection that gets destroyed when
     * all preceding data has been handled. On its destruction, it is safe
     * to purge all resources of the stream. */
    ap_log_cerror(APLOG_MARK, APLOG_TRACE2, 0, session->c1,
                  H2_STRM_MSG(stream, "adding h2_eos to c1 out"));
    b = h2_bucket_eos_create(session->c1->bucket_alloc, stream);
    APR_BRIGADE_INSERT_TAIL(session->bbtmp, b);
    h2_c1_io_append(&session->io, session->bbtmp);
    apr_brigade_cleanup(session->bbtmp);
}

static void on_stream_state_enter(void *ctx, h2_stream *stream)
{
    h2_session *session = ctx;

    ap_log_cerror(APLOG_MARK, APLOG_TRACE2, 0, session->c1,
                  H2_STRM_MSG(stream, "entered state"));
    switch (stream->state) {
        case H2_SS_IDLE: /* stream was created */
            ev_stream_created(session, stream);
            break;
        case H2_SS_OPEN: /* stream has request headers */
        case H2_SS_RSVD_L:
            ev_stream_open(session, stream);
            break;
        case H2_SS_CLOSED_L: /* stream output was closed, but remote end is not */
            /* If the stream is still being processed, it could still be reading
             * its input (theoretically, http request hangling does not normally).
             * But when processing is done, we need to cancel the stream as no
             * one is consuming the input any longer.
             * This happens, for example, on a large POST when the response
             * is ready early due to the POST being denied. */
            if (!h2_mplx_c1_stream_is_running(session->mplx, stream)) {
                ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, session->c1,
                              H2_STRM_LOG(APLOGNO(10305), stream, "remote close missing"));
                nghttp2_submit_rst_stream(session->ngh2, NGHTTP2_FLAG_NONE,
                                          stream->id, H2_ERR_NO_ERROR);
            }
            break;
        case H2_SS_CLOSED_R: /* stream input was closed */
            break;
        case H2_SS_CLOSED: /* stream in+out were closed */
            ev_stream_closed(session, stream);
            break;
        case H2_SS_CLEANUP:
            nghttp2_session_set_stream_user_data(session->ngh2, stream->id, NULL);
            h2_mplx_c1_stream_cleanup(session->mplx, stream, &session->open_streams);
            ++session->streams_done;
            update_child_status(session, SERVER_BUSY_WRITE, "done", stream);
            break;
        default:
            break;
    }
}

static void on_stream_event(void *ctx, h2_stream *stream, h2_stream_event_t ev)
{
    h2_session *session = ctx;
    switch (ev) {
        case H2_SEV_IN_DATA_PENDING:
            session->input_flushed = 1;
            break;
        case H2_SEV_OUT_C1_BLOCK:
            h2_iq_append(session->out_c1_blocked, stream->id);
            break;
        default:
            /* NOP */
            break;
    }
}

static void on_stream_state_event(void *ctx, h2_stream *stream, 
                                  h2_stream_event_t ev)
{
    h2_session *session = ctx;
    switch (ev) {
        case H2_SEV_CANCELLED:
            if (session->state != H2_SESSION_ST_DONE) {
                nghttp2_submit_rst_stream(session->ngh2, NGHTTP2_FLAG_NONE, 
                                          stream->id, stream->rst_error);
            }
            break;
        default:
            /* NOP */
            break;
    }
}

void h2_session_dispatch_event(h2_session *session, h2_session_event_t ev,
                               apr_status_t arg, const char *msg)
{
    switch (ev) {
        case H2_SESSION_EV_INIT:
            h2_session_ev_init(session, arg, msg);
            break;            
        case H2_SESSION_EV_INPUT_PENDING:
            h2_session_ev_input_pending(session, arg, msg);
            break;
        case H2_SESSION_EV_INPUT_EXHAUSTED:
            h2_session_ev_input_exhausted(session, arg, msg);
            break;
        case H2_SESSION_EV_LOCAL_GOAWAY:
            h2_session_ev_local_goaway(session, arg, msg);
            break;
        case H2_SESSION_EV_REMOTE_GOAWAY:
            h2_session_ev_remote_goaway(session, arg, msg);
            break;
        case H2_SESSION_EV_CONN_ERROR:
            h2_session_ev_conn_error(session, arg, msg);
            break;
        case H2_SESSION_EV_PROTO_ERROR:
            h2_session_ev_proto_error(session, arg, msg);
            break;
        case H2_SESSION_EV_CONN_TIMEOUT:
            h2_session_ev_conn_timeout(session, arg, msg);
            break;
        case H2_SESSION_EV_NGH2_DONE:
            h2_session_ev_ngh2_done(session, arg, msg);
            break;
        case H2_SESSION_EV_MPM_STOPPING:
            h2_session_ev_mpm_stopping(session, arg, msg);
            break;
        case H2_SESSION_EV_PRE_CLOSE:
            h2_session_ev_pre_close(session, arg, msg);
            break;
        case H2_SESSION_EV_NO_MORE_STREAMS:
            h2_session_ev_no_more_streams(session);
            break;
        default:
            ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, session->c1,
                          H2_SSSN_MSG(session, "unknown event %d"), ev);
            break;
    }
}

static void unblock_c1_out(h2_session *session) {
    int sid;

    while ((sid = h2_iq_shift(session->out_c1_blocked)) > 0) {
        nghttp2_session_resume_data(session->ngh2, sid);
    }
}

static int h2_send_flow_blocked(h2_session *session)
{
    /* We are completely send blocked if either the connection window
     * is 0 or all stream flow windows are 0. */
    return ((nghttp2_session_get_remote_window_size(session->ngh2) <= 0) ||
             h2_mplx_c1_all_streams_send_win_exhausted(session->mplx));
}

apr_status_t h2_session_process(h2_session *session, int async,
                                int *pkeepalive)
{
    apr_status_t status = APR_SUCCESS;
    conn_rec *c = session->c1;
    int rv, mpm_state, trace = APLOGctrace3(c);

    *pkeepalive = 0;
    if (trace) {
        ap_log_cerror( APLOG_MARK, APLOG_TRACE3, status, c,
                      H2_SSSN_MSG(session, "process start, async=%d"), async);
    }

    if (H2_SESSION_ST_INIT == session->state) {
        if (!h2_protocol_is_acceptable_c1(c, session->r, 1)) {
            const char *msg = nghttp2_strerror(NGHTTP2_INADEQUATE_SECURITY);
            update_child_status(session, SERVER_BUSY_READ, msg, NULL);
            h2_session_shutdown(session, APR_EINVAL, msg, 1);
        }
        else {
            update_child_status(session, SERVER_BUSY_READ, "init", NULL);
            status = h2_session_start(session, &rv);
            ap_log_cerror(APLOG_MARK, APLOG_DEBUG, status, c,
                          H2_SSSN_LOG(APLOGNO(03079), session,
                          "started on %s:%d"),
                          session->s->server_hostname,
                          c->local_addr->port);
            if (status != APR_SUCCESS) {
                h2_session_dispatch_event(session,
                               H2_SESSION_EV_CONN_ERROR, status, NULL);
            }
            else {
                h2_session_dispatch_event(session, H2_SESSION_EV_INIT, 0, NULL);
            }
        }
    }

    while (session->state != H2_SESSION_ST_DONE) {

        /* PR65731: we may get a new connection to process while the
         * MPM already is stopping. For example due to having reached
         * MaxRequestsPerChild limit.
         * Since this is supposed to handle things gracefully, we need to:
         * a) fully initialize the session before GOAWAYing
         * b) give the client the chance to submit at least one request
         */
        if (session->state != H2_SESSION_ST_INIT /* no longer intializing */
            && session->local.accepted_max > 0   /* have gotten at least one stream */
            && session->local.accepting          /* have not already locally shut down */
            && !ap_mpm_query(AP_MPMQ_MPM_STATE, &mpm_state)) {
            if (mpm_state == AP_MPMQ_STOPPING) {
                h2_session_dispatch_event(session, H2_SESSION_EV_MPM_STOPPING, 0, NULL);
            }
        }

        session->status[0] = '\0';
        
        if (h2_session_want_send(session)) {
            h2_session_send(session);
        }
        else if (!nghttp2_session_want_read(session->ngh2)) {
            h2_session_dispatch_event(session, H2_SESSION_EV_NGH2_DONE, 0, NULL);
        }

        if (!h2_iq_empty(session->ready_to_process)) {
            h2_mplx_c1_process(session->mplx, session->ready_to_process,
                               get_stream, stream_pri_cmp, session,
                               &session->open_streams);
            transit(session, "scheduled stream", H2_SESSION_ST_BUSY);
        }

        if (session->input_flushed) {
            transit(session, "forwarded input", H2_SESSION_ST_BUSY);
            session->input_flushed = 0;
        }

        if (!h2_iq_empty(session->out_c1_blocked)) {
            unblock_c1_out(session);
            transit(session, "unblocked output", H2_SESSION_ST_BUSY);
        }

        if (session->reprioritize) {
            h2_mplx_c1_reprioritize(session->mplx, stream_pri_cmp, session);
            session->reprioritize = 0;
        }

        if (h2_session_want_send(session)) {
            h2_session_send(session);
        }

        status = h2_c1_io_assure_flushed(&session->io);
        if (APR_SUCCESS != status) {
            h2_session_dispatch_event(session, H2_SESSION_EV_CONN_ERROR, status, NULL);
        }

        switch (session->state) {
        case H2_SESSION_ST_INIT:
            ap_assert(0);
            h2_c1_read(session);
            break;

        case H2_SESSION_ST_IDLE:
            ap_assert(session->open_streams == 0);
            ap_assert(nghttp2_session_want_read(session->ngh2));
            if (!h2_session_want_send(session)) {
                /* Give any new incoming request a short grace period to
                 * arrive while we are still hot and return to the mpm
                 * connection handling when nothing really happened. */
                h2_c1_read(session);
                if (H2_SESSION_ST_IDLE == session->state) {
                    if (async) {
                        ap_log_cerror(APLOG_MARK, APLOG_DEBUG, status, c,
                                      H2_SSSN_LOG(APLOGNO(10306), session,
                                      "returning to mpm c1 monitoring"));
                        goto leaving;
                    }
                    else {
                        /* Not an async mpm, we must continue waiting
                         * for client data to arrive until the configured
                         * server Timeout/KeepAliveTimeout happens */
                        apr_time_t timeout = ((session->open_streams == 0) &&
                                              session->remote.emitted_count)?
                            session->s->keep_alive_timeout :
                            session->s->timeout;
                        ap_log_cerror(APLOG_MARK, APLOG_TRACE2, status, c,
                                      H2_SSSN_MSG(session, "polling timeout=%d"),
                                      (int)apr_time_sec(timeout));
                        status = h2_mplx_c1_poll(session->mplx, timeout,
                                                 on_stream_input,
                                                 on_stream_output, session);
                        if (APR_STATUS_IS_TIMEUP(status)) {
                            if (session->open_streams == 0) {
                                h2_session_dispatch_event(session,
                                    H2_SESSION_EV_CONN_TIMEOUT, status, NULL);
                                break;
                            }
                        }
                        else if (APR_SUCCESS != status) {
                            h2_session_dispatch_event(session,
                                H2_SESSION_EV_CONN_ERROR, status, NULL);
                            break;
                        }
                    }
                }
            }
            else {
                transit(session, "c1 io pending", H2_SESSION_ST_BUSY);
            }
            break;

        case H2_SESSION_ST_BUSY:
            /* IO happening in and out. Make sure we react to c2 events
             * inbetween send and receive. */
            status = h2_mplx_c1_poll(session->mplx, 0,
                                     on_stream_input, on_stream_output, session);
            if (APR_SUCCESS != status && !APR_STATUS_IS_TIMEUP(status)) {
                h2_session_dispatch_event(session, H2_SESSION_EV_CONN_ERROR, status, NULL);
                break;
            }
            h2_c1_read(session);
            break;

        case H2_SESSION_ST_WAIT:
            /* In this state, we might have returned processing to the MPM
             * before. On a connection socket event, we are invoked again and
             * need to process any input before proceeding. */
            h2_c1_read(session);
            if (session->state != H2_SESSION_ST_WAIT) {
                break;
            }

            status = h2_c1_io_assure_flushed(&session->io);
            if (APR_SUCCESS != status) {
                h2_session_dispatch_event(session, H2_SESSION_EV_CONN_ERROR, status, NULL);
                break;
            }
            if (session->open_streams == 0) {
                h2_session_dispatch_event(session, H2_SESSION_EV_NO_MORE_STREAMS,
                                          0, "streams really done");
                if (session->state != H2_SESSION_ST_WAIT) {
                    break;
                }
            }
            else if (async && h2_send_flow_blocked(session)) {
                /* By returning to the MPM, we do not block a worker
                 * and async wait for the client send window updates. */
                ap_log_cerror(APLOG_MARK, APLOG_DEBUG, status, c,
                              H2_SSSN_LOG(APLOGNO(10502), session,
                              "BLOCKED, return to mpm c1 monitoring"));
                goto leaving;
            }

            /* No IO happening and input is exhausted. Wait with
             * the c1 connection timeout for sth to happen in our c1/c2 sockets/pipes */
            ap_log_cerror(APLOG_MARK, APLOG_TRACE2, status, c,
                          H2_SSSN_MSG(session, "polling timeout=%d, open_streams=%d"),
                          (int)apr_time_sec(session->s->timeout), session->open_streams);
            status = h2_mplx_c1_poll(session->mplx, session->s->timeout,
                                     on_stream_input, on_stream_output, session);
            if (APR_STATUS_IS_TIMEUP(status)) {
                /* If we timeout without streams open, no new request from client
                 * arrived.
                 * If we timeout without nghttp2 wanting to write something, but
                 * all open streams have something to send, it means we are
                 * blocked on HTTP/2 flow control and the client did not send
                 * WINDOW_UPDATEs to us. */
                if (session->open_streams == 0 ||
                    (!h2_session_want_send(session) &&
                     h2_mplx_c1_all_streams_want_send_data(session->mplx))) {
                    h2_session_dispatch_event(session, H2_SESSION_EV_CONN_TIMEOUT, status, NULL);
                    break;
                }
            }
            else if (APR_SUCCESS != status) {
                h2_session_dispatch_event(session, H2_SESSION_EV_CONN_ERROR, status, NULL);
                break;
            }
            break;

        case H2_SESSION_ST_DONE:
            h2_c1_read(session);
            break;

        default:
            ap_log_cerror(APLOG_MARK, APLOG_ERR, APR_EGENERAL, c,
                          H2_SSSN_LOG(APLOGNO(03080), session,
                          "unknown state"));
            h2_session_dispatch_event(session, H2_SESSION_EV_PROTO_ERROR, APR_EGENERAL, NULL);
            break;
        }
    }

leaving:
    /* entering KeepAlive timing when we have no more open streams AND
     * we have processed at least one stream. */
    *pkeepalive = (session->open_streams == 0 && session->remote.emitted_count);
    if (trace) {
        ap_log_cerror(APLOG_MARK, APLOG_TRACE3, status, c,
                      H2_SSSN_MSG(session, "process returns, keepalive=%d"),
                      *pkeepalive);
    }
    h2_mplx_c1_going_keepalive(session->mplx);

    if (session->state == H2_SESSION_ST_DONE) {
        if (session->local.error) {
            char buffer[128];
            const char *msg;
            if (session->local.error_msg) {
                msg = session->local.error_msg;
            }
            else {
                msg = apr_strerror(session->local.error, buffer, sizeof(buffer));
            }
            update_child_status(session, SERVER_CLOSING, msg, NULL);
        }
        else {
            update_child_status(session, SERVER_CLOSING, "done", NULL);
        }
    }
    else if (APR_STATUS_IS_EOF(status)
            || APR_STATUS_IS_ECONNRESET(status) 
            || APR_STATUS_IS_ECONNABORTED(status)) {
        h2_session_dispatch_event(session, H2_SESSION_EV_CONN_ERROR, status, NULL);
        update_child_status(session, SERVER_CLOSING, "error", NULL);
    }

    return (session->state == H2_SESSION_ST_DONE)? APR_EOF : APR_SUCCESS;
}

apr_status_t h2_session_pre_close(h2_session *session, int async)
{
    apr_status_t status;
    
    ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, session->c1,
                  H2_SSSN_MSG(session, "pre_close"));
    h2_session_dispatch_event(session, H2_SESSION_EV_PRE_CLOSE, 0,
        (session->state == H2_SESSION_ST_IDLE)? "timeout" : NULL);
    status = session_cleanup(session, "pre_close");
    if (status == APR_SUCCESS) {
        /* no one should hold a reference to this session any longer and
         * the h2_conn_ctx_twas removed from the connection.
         * Take the pool (and thus all subpools etc. down now, instead of
         * during cleanup of main connection pool. */
        apr_pool_destroy(session->pool);
    }
    return status;
}
