
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_event_quic_connection.h>


// @see https://source.chromium.org/chromium/chromium/src/+/master:net/third_party/quiche/src/quic/core/quic_mtu_discovery.cc

static ngx_int_t
ngx_quic_mtu_should_probe(ngx_quic_mtu_t *mtu, uint64_t largest_sent_packet)
{
    if (mtu->process) {
        return 0;
    }

    if (mtu->min_probe_length >= mtu->max_probe_length) {
        return 0;
    }

    if (mtu->remaining_probe_count == 0) {
        return 0;
    }

    if (largest_sent_packet < mtu->next_probe_at) {
        return 0;
    }

    return 1;
}


static size_t
ngx_quic_mtu_next_probe_packet_length(ngx_quic_mtu_t *mtu)
{
    size_t  normal_next_probe_length = (mtu->min_probe_length + mtu->max_probe_length + 1) / 2;

    if (mtu->remaining_probe_count == 1 &&
        normal_next_probe_length > mtu->last_probe_length)
    {
        /* If the previous probe succeeded, and there is only one last probe to
         * end, use |max_probe_length_| for the last probe.
         */
        return mtu->max_probe_length;
    }

    return normal_next_probe_length;
}


static size_t
ngx_quic_mtu_get_updated_probe_size(ngx_quic_mtu_t *mtu, uint64_t largest_sent_packet)
{
    size_t  probe_packet_length = ngx_quic_mtu_next_probe_packet_length(mtu);

    if (probe_packet_length == mtu->last_probe_length) {
        /* The next probe packet is as big as the previous one. Assuming the
         * previous one exceeded MTU, we need to decrease the probe packet length.
         */
        mtu->max_probe_length = probe_packet_length;
    }

    mtu->last_probe_length = ngx_quic_mtu_next_probe_packet_length(mtu);

    mtu->packets_between_probes *= 2;
    mtu->next_probe_at = largest_sent_packet + mtu->packets_between_probes + 1;

    if (mtu->remaining_probe_count > 0) {
        --mtu->remaining_probe_count;
    }

    return mtu->last_probe_length;
}


ngx_int_t
ngx_quic_mtu_probe(ngx_connection_t *c)
{
    ngx_quic_connection_t  *qc;
    ngx_quic_send_ctx_t    *ctx;
    ngx_quic_path_t        *path;
    ngx_quic_frame_t       *frame;
    size_t                  len;

    qc = ngx_quic_get_connection(c);
    ctx = ngx_quic_get_send_ctx(qc, ssl_encryption_application);

    if (!ngx_quic_mtu_should_probe(&qc->mtu, ctx->pnum)) {
        return NGX_DECLINED;
    }

    path = ngx_quic_get_socket(c)->path;

    if (path == NULL) {
        return NGX_DECLINED;
    }

    frame = ngx_quic_alloc_frame(c);
    if (frame == NULL) {
        return NGX_OK;
    }

    frame->level = ctx->level;
    frame->type = NGX_QUIC_FT_PING;
    frame->flush = 1;
    frame->need_ack = 1;
    frame->probe = 1;

    len = ngx_quic_mtu_get_updated_probe_size(&qc->mtu, ctx->pnum);

    if (ngx_quic_frame_sendto_dont_fragment(c, frame, len, path->sockaddr,  path->socklen) == NGX_ERROR) {
        return NGX_ERROR;
    }

    qc->mtu.process = 1;
    ngx_queue_insert_tail(&ctx->sent, &frame->queue);

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0,
        "quic mtu discover sent new packet: %z", len);

    return NGX_OK;
}


void
ngx_quic_mtu_ack(ngx_connection_t *c, ngx_quic_frame_t *frame)
{
    ngx_quic_connection_t  *qc;

    qc = ngx_quic_get_connection(c);

    qc->mtu.min_probe_length = frame->plen;
    qc->ctp.max_udp_payload_size = frame->plen;

    qc->mtu.process = 0;

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0,
        "quic mtu discover ack packet: %z", qc->ctp.max_udp_payload_size);
}


void
ngx_quic_mtu_lost(ngx_connection_t *c, ngx_quic_frame_t *frame)
{
    ngx_quic_connection_t  *qc;

    qc = ngx_quic_get_connection(c);
    qc->mtu.process = 0;

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0,
        "quic mtu discover lost packet: %z", qc->mtu.last_probe_length);
}
