#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    uint8_t flags;
    uint8_t encoding_type;
    uint16_t frame_index;
    uint16_t seq_length;
    uint32_t seq_size;
} swp_rx_meta_t;

typedef bool (*swp_transport_frame_visitor_t)(const uint8_t *data,
                                              uint16_t len,
                                              const swp_rx_meta_t *meta,
                                              bool *stream_complete,
                                              void *user_ctx);

bool swp_transport_configure_malform(uint32_t count, const char *kind);

bool swp_transport_open(const char *port, int baud);
void swp_transport_close(void);

bool swp_transport_send(const uint8_t *data,
                        uint32_t len,
                        uint8_t flags,
                        uint8_t encoding_type);

bool swp_transport_receive(uint8_t *out,
                                    size_t out_capacity,
                                    uint16_t *out_len,
                           uint32_t timeout_ms);

bool swp_transport_receive_ex(uint8_t *out,
                                        size_t out_capacity,
                              uint16_t *out_len,
                              swp_rx_meta_t *meta,
                              uint32_t timeout_ms);

bool swp_transport_receive_frame_ex(uint8_t *out,
                                    size_t out_capacity,
                                    uint16_t *out_len,
                                    swp_rx_meta_t *meta,
                                    uint32_t timeout_ms);

bool swp_transport_receive_stream_ex(swp_transport_frame_visitor_t visitor,
                                     void *user_ctx,
                                     uint32_t timeout_ms,
                                     uint32_t complete_settle_ms);

#ifdef __cplusplus
}
#endif
