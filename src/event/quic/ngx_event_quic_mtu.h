
#ifndef _NGX_EVENT_QUIC_MTU_H_INCLUDED_
#define _NGX_EVENT_QUIC_MTU_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


ngx_int_t
ngx_quic_mtu_probe(ngx_connection_t *c);

void
ngx_quic_mtu_ack(ngx_connection_t *c, ngx_quic_frame_t *frame);

void
ngx_quic_mtu_lost(ngx_connection_t *c, ngx_quic_frame_t *frame);


#endif /* _NGX_EVENT_QUIC_MTU_H_INCLUDED_ */
