#include "swp_bridge.h"

#include "serial_port_linux_c_api.h"
#include "sliding_window_protocol_16bit.h"
#include "swp_internal.h"

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

static void swp_fill_rx_meta(swp_rx_meta_t *meta, const Frame *frame);
static bool swp_pop_next_in_order_frame(uint8_t *out,
                                        size_t out_capacity,
                                        uint16_t *out_len,
                                        swp_rx_meta_t *meta);
static bool swp_process_receive_control(FrameType frame_type,
                                        const uint8_t *ctrl_data,
                                        uint8_t ctrl_len);

typedef enum {
    SWP_MALFORM_NONE = 0,
    SWP_MALFORM_CRC_PAYLOAD,
    SWP_MALFORM_CRC_HEADER,
    SWP_MALFORM_TOKEN_BAD,
    SWP_MALFORM_LEN_OVER,
    SWP_MALFORM_LEN_MISMATCH,
    SWP_MALFORM_SEQ_JUMP,
    SWP_MALFORM_ENCODING_INVALID,
    SWP_MALFORM_TRUNCATE_TAIL,
    SWP_MALFORM_ALL,
} swp_malform_kind_t;

typedef struct {
    uint32_t configured_count;
    uint32_t remaining_count;
    uint32_t injected_count;
    swp_malform_kind_t kind;
} swp_malform_config_t;

static swp_malform_config_t g_swp_malform = {0u, 0u, 0u, SWP_MALFORM_NONE};

static const char *swp_malform_kind_name(swp_malform_kind_t kind) {
    switch (kind) {
        case SWP_MALFORM_CRC_PAYLOAD: return "crc_payload";
        case SWP_MALFORM_CRC_HEADER: return "crc_header";
        case SWP_MALFORM_TOKEN_BAD: return "token_bad";
        case SWP_MALFORM_LEN_OVER: return "len_over";
        case SWP_MALFORM_LEN_MISMATCH: return "len_mismatch";
        case SWP_MALFORM_SEQ_JUMP: return "seq_jump";
        case SWP_MALFORM_ENCODING_INVALID: return "encoding_invalid";
        case SWP_MALFORM_TRUNCATE_TAIL: return "truncate_tail";
        case SWP_MALFORM_ALL: return "all";
        case SWP_MALFORM_NONE:
        default:
            return "none";
    }
}

static bool swp_parse_malform_kind(const char *kind_str, swp_malform_kind_t *kind) {
    if (kind == NULL) {
        return false;
    }

    if (kind_str == NULL || kind_str[0] == '\0' || strcmp(kind_str, "none") == 0) {
        *kind = SWP_MALFORM_NONE;
        return true;
    }
    if (strcmp(kind_str, "crc_payload") == 0) {
        *kind = SWP_MALFORM_CRC_PAYLOAD;
        return true;
    }
    if (strcmp(kind_str, "crc_header") == 0) {
        *kind = SWP_MALFORM_CRC_HEADER;
        return true;
    }
    if (strcmp(kind_str, "token_bad") == 0) {
        *kind = SWP_MALFORM_TOKEN_BAD;
        return true;
    }
    if (strcmp(kind_str, "len_over") == 0) {
        *kind = SWP_MALFORM_LEN_OVER;
        return true;
    }
    if (strcmp(kind_str, "len_mismatch") == 0) {
        *kind = SWP_MALFORM_LEN_MISMATCH;
        return true;
    }
    if (strcmp(kind_str, "seq_jump") == 0) {
        *kind = SWP_MALFORM_SEQ_JUMP;
        return true;
    }
    if (strcmp(kind_str, "encoding_invalid") == 0) {
        *kind = SWP_MALFORM_ENCODING_INVALID;
        return true;
    }
    if (strcmp(kind_str, "truncate_tail") == 0) {
        *kind = SWP_MALFORM_TRUNCATE_TAIL;
        return true;
    }
    if (strcmp(kind_str, "all") == 0) {
        *kind = SWP_MALFORM_ALL;
        return true;
    }

    return false;
}

static swp_malform_kind_t swp_resolve_effective_malform_kind(swp_malform_kind_t configured_kind) {
    static const swp_malform_kind_t kKinds[] = {
        SWP_MALFORM_CRC_PAYLOAD,
        SWP_MALFORM_CRC_HEADER,
        SWP_MALFORM_TOKEN_BAD,
        SWP_MALFORM_LEN_OVER,
        SWP_MALFORM_LEN_MISMATCH,
        SWP_MALFORM_SEQ_JUMP,
        SWP_MALFORM_ENCODING_INVALID,
        SWP_MALFORM_TRUNCATE_TAIL,
    };

    if (configured_kind != SWP_MALFORM_ALL) {
        return configured_kind;
    }

    return kKinds[g_swp_malform.injected_count % (sizeof(kKinds) / sizeof(kKinds[0]))];
}

static bool swp_should_malform_frame(const Frame *frame, swp_malform_kind_t *effective_kind) {
    if (frame == NULL || effective_kind == NULL) {
        return false;
    }
    if (g_swp_malform.remaining_count == 0u || g_swp_malform.kind == SWP_MALFORM_NONE) {
        return false;
    }

    const uint8_t slot = (uint8_t)(frame->frame_index % WINDOW_SIZE);
    const bool is_retransmit = send_window[slot].sent &&
                               send_window[slot].frame.frame_index == frame->frame_index;
    if (is_retransmit) {
        return false;
    }

    *effective_kind = swp_resolve_effective_malform_kind(g_swp_malform.kind);
    g_swp_malform.remaining_count--;
    g_swp_malform.injected_count++;
    fprintf(stderr,
            "[HOST-WIRE] EVT=MALFORM_TX kind=%s frame=%u remaining=%u\n",
            swp_malform_kind_name(*effective_kind),
            (unsigned)frame->frame_index,
            (unsigned)g_swp_malform.remaining_count);
    return true;
}

static inline void swp_le16_write(uint8_t *buf, uint16_t value) {
    buf[0] = (uint8_t)(value & 0xFFu);
    buf[1] = (uint8_t)((value >> 8) & 0xFFu);
}

static inline void swp_le32_write(uint8_t *buf, uint32_t value) {
    buf[0] = (uint8_t)(value & 0xFFu);
    buf[1] = (uint8_t)((value >> 8) & 0xFFu);
    buf[2] = (uint8_t)((value >> 16) & 0xFFu);
    buf[3] = (uint8_t)((value >> 24) & 0xFFu);
}

bool swp_transport_configure_malform(uint32_t count, const char *kind) {
    swp_malform_kind_t parsed_kind = SWP_MALFORM_NONE;
    if (!swp_parse_malform_kind(kind, &parsed_kind)) {
        return false;
    }
    if (count == 0u) {
        parsed_kind = SWP_MALFORM_NONE;
    }

    g_swp_malform.configured_count = count;
    g_swp_malform.remaining_count = count;
    g_swp_malform.injected_count = 0u;
    g_swp_malform.kind = parsed_kind;
    return true;
}

static bool swp_drain_in_order(uint8_t *out,
                               size_t out_capacity,
                               uint16_t *out_len,
                               swp_rx_meta_t *meta,
                               bool *sequence_done) {
    while (recv_window[0].received && recv_window[0].frame.frame_index == expected_frame_index) {
        Frame *current = &recv_window[0].frame;
        const size_t next_len = (size_t)(*out_len) + (size_t)current->data_length;
        if (next_len > out_capacity || next_len > (size_t)UINT16_MAX) {
            return false;
        }

        memcpy(out + *out_len, current->data, current->data_length);
        *out_len = (uint16_t)next_len;
        swp_fill_rx_meta(meta, current);

        const bool is_last_frame = (current->flags & FLAG_LAST_FRAME) != 0u;
        for (int i = 1; i < WINDOW_SIZE; ++i) {
            recv_window[i - 1] = recv_window[i];
        }
        recv_window[WINDOW_SIZE - 1].received = false;
        expected_frame_index = (uint16_t)((expected_frame_index + 1u) % MAX_FRAME_INDEX);

        if (is_last_frame) {
            *sequence_done = true;
            break;
        }
    }

    return true;
}

static bool swp_pop_next_in_order_frame(uint8_t *out,
                                        size_t out_capacity,
                                        uint16_t *out_len,
                                        swp_rx_meta_t *meta) {
    if (!recv_window[0].received || recv_window[0].frame.frame_index != expected_frame_index) {
        return false;
    }

    Frame *current = &recv_window[0].frame;
    if ((size_t)current->data_length > out_capacity) {
        return false;
    }

    memcpy(out, current->data, current->data_length);
    *out_len = current->data_length;
    swp_fill_rx_meta(meta, current);

    for (int i = 1; i < WINDOW_SIZE; ++i) {
        recv_window[i - 1] = recv_window[i];
    }
    recv_window[WINDOW_SIZE - 1].received = false;
    expected_frame_index = (uint16_t)((expected_frame_index + 1u) % MAX_FRAME_INDEX);
    return true;
}

volatile uint16_t uartRxBuffer_count = 0;
uint16_t uartRxBuffer_capacity = 1;
uint8_t uartRxBuffer[1] = {0};

bool uart_send_byte(uint8_t byte) {
    return serial_send_byte(byte);
}

uint8_t uart_receive_byte(void) {
    return serial_receive_byte();
}

bool uart_RX_available(void) {
    return serial_rx_available();
}

uint32_t millis(void) {
    return serial_millis_now();
}

void uart_flush_tx(void) {
    serial_flush_tx();
}

void swp_hook_post_nack(void) {
    fprintf(stderr,
            "[HOST-WIRE] EVT=NACK_TX exp=%u base=%u next=%u drop=%u seq_drop=%u\n",
            (unsigned)expected_frame_index,
            (unsigned)base_frame_index,
            (unsigned)next_frame_index,
            (unsigned)conn_state.dropped_frames,
            (unsigned)conn_state.sequence_mismatch_drop);
}

void send_frame_struct(Frame *frame) {
    uint8_t header[12];
    uint16_t frame_index = frame->frame_index;
    uint16_t data_length = frame->data_length;
    uint8_t encoding_type = frame->encoding_type;
    uint16_t token = frame->token;
    swp_malform_kind_t effective_kind = SWP_MALFORM_NONE;
    const bool malform = swp_should_malform_frame(frame, &effective_kind);

    if (malform) {
        switch (effective_kind) {
            case SWP_MALFORM_LEN_OVER:
                data_length = (uint16_t)(MAX_DATA_SIZE + 1u);
                break;
            case SWP_MALFORM_LEN_MISMATCH:
                data_length = (uint16_t)(frame->data_length + 1u);
                break;
            case SWP_MALFORM_TOKEN_BAD:
                token = 0x55AAu;
                break;
            case SWP_MALFORM_SEQ_JUMP:
                frame_index = (uint16_t)((frame_index + WINDOW_SIZE + 3u) % MAX_FRAME_INDEX);
                break;
            case SWP_MALFORM_ENCODING_INVALID:
                encoding_type = 0xFFu;
                break;
            case SWP_MALFORM_CRC_PAYLOAD:
            case SWP_MALFORM_CRC_HEADER:
            case SWP_MALFORM_TRUNCATE_TAIL:
            case SWP_MALFORM_ALL:
            case SWP_MALFORM_NONE:
            default:
                break;
        }
    }

    header[0] = frame->flags;
    swp_le16_write(&header[1], frame_index);
    swp_le16_write(&header[3], frame->seq_length);
    swp_le32_write(&header[5], frame->seq_size);
    swp_le16_write(&header[9], data_length);
    header[11] = encoding_type;

    uint16_t crc = 0xFFFFu;
    for (uint16_t i = 0; i < (uint16_t)sizeof(header); ++i) {
        crc = crc16_ccitt_update(crc, header[i]);
    }
    for (uint16_t i = 0; i < frame->data_length; ++i) {
        crc = crc16_ccitt_update(crc, frame->data[i]);
    }
    crc = crc16_ccitt_update(crc, (uint8_t)(token & 0xFFu));
    crc = crc16_ccitt_update(crc, (uint8_t)((token >> 8) & 0xFFu));
    frame->crc = crc;

    uint8_t payload_mutation_index = 0u;
    const bool mutate_payload = malform && effective_kind == SWP_MALFORM_CRC_PAYLOAD;
    const bool mutate_header = malform && effective_kind == SWP_MALFORM_CRC_HEADER;
    if (mutate_payload) {
        payload_mutation_index = (frame->data_length > 0u) ? 0u : 0xFFu;
    }

    uart_send_byte(FRAME_BYTE);
    for (uint16_t i = 0; i < (uint16_t)sizeof(header); ++i) {
        uint8_t byte = header[i];
        if (mutate_header && i == 0u) {
            byte ^= 0x01u;
        }
        send_escaped_byte(byte);
    }
    for (uint16_t i = 0; i < frame->data_length; ++i) {
        uint8_t byte = frame->data[i];
        if (mutate_payload && payload_mutation_index != 0xFFu && i == payload_mutation_index) {
            byte ^= 0x01u;
        }
        send_escaped_byte(byte);
    }
    send_escaped_byte((uint8_t)(token & 0xFFu));
    send_escaped_byte((uint8_t)((token >> 8) & 0xFFu));
    send_escaped_byte((uint8_t)(crc & 0xFFu));
    send_escaped_byte((uint8_t)((crc >> 8) & 0xFFu));

    if (!(malform && effective_kind == SWP_MALFORM_TRUNCATE_TAIL)) {
        uart_send_byte(FRAME_BYTE);
    }

    uart_flush_tx();
}

static void swp_fill_rx_meta(swp_rx_meta_t *meta, const Frame *frame) {
    if (!meta || !frame) {
        return;
    }

    meta->flags = frame->flags;
    meta->encoding_type = frame->encoding_type;
    meta->frame_index = frame->frame_index;
    meta->seq_length = frame->seq_length;
    meta->seq_size = frame->seq_size;
}

bool swp_transport_open(const char *port, int baud) {
    if (!serial_open_port(port, baud)) {
        return false;
    }
    g_swp_malform.remaining_count = g_swp_malform.configured_count;
    g_swp_malform.injected_count = 0u;
    init_sliding_window_protocol();
    return true;
}

void swp_transport_close(void) {
    serial_close_port();
}

bool swp_transport_send(const uint8_t *data,
                        uint32_t len,
                        uint8_t flags,
                        uint8_t encoding_type) {
    static const uint8_t k_empty_payload = 0;

    if (!data && len > 0) {
        return false;
    }

    const uint8_t *payload = data;
    if (len == 0) {
        payload = &k_empty_payload;
        sliding_window_send_payload(payload, 0u, flags, encoding_type);
        return true;
    }

    sliding_window_send_fragmented(payload, len, flags, encoding_type);
    return true;
}

bool swp_transport_receive(uint8_t *out,
                           size_t out_capacity,
                           uint16_t *out_len,
                           uint32_t timeout_ms) {
    return swp_transport_receive_ex(out, out_capacity, out_len, NULL, timeout_ms);
}

static bool swp_process_receive_control(FrameType frame_type,
                                        const uint8_t *ctrl_data,
                                        uint8_t ctrl_len) {
    if (frame_type == FRAME_TYPE_ACK && ctrl_len >= 3u) {
        const uint16_t sack_base = (uint16_t)(((uint16_t)ctrl_data[0] << 8) | ctrl_data[1]);
        const uint8_t window_frames = ctrl_data[2];
        handle_sack_ack(sack_base, window_frames);
        return true;
    }

    if (frame_type == FRAME_TYPE_NACK) {
        handle_nack_retransmit();
        return true;
    }

    if (frame_type == FRAME_TYPE_RESET) {
        handle_reset_frame();
        reset_sliding_window_receiver();
        return true;
    }

    return false;
}

bool swp_transport_receive_ex(uint8_t *out,
                              size_t out_capacity,
                              uint16_t *out_len,
                              swp_rx_meta_t *meta,
                              uint32_t timeout_ms) {
    if (!out || !out_len || out_capacity == 0u) {
        return false;
    }

    *out_len = 0;
    if (meta) {
        *meta = (swp_rx_meta_t){0};
    }

    reset_sliding_window_receiver();

    const uint32_t start = millis();
    bool sequence_done = false;
    while ((millis() - start) < timeout_ms) {
        FrameType frame_type = FRAME_TYPE_UNKNOWN;
        Frame frame = {0};
        uint8_t ctrl_data[10] = {0};
        uint8_t ctrl_len = 0;
        const uint32_t elapsed = millis() - start;
        const uint32_t remaining_ms = timeout_ms - elapsed;

        if (!receive_any_frame_timed(&frame_type,
                                     &frame,
                                     ctrl_data,
                                     &ctrl_len,
                                     remaining_ms,
                                     100u)) {
            if (base_frame_index != next_frame_index) {
                check_timeouts_and_retransmit();
            }
            continue;
        }

        if (swp_process_receive_control(frame_type, ctrl_data, ctrl_len)) {
            continue;
        }

        if (!is_valid_encoding_type(frame.encoding_type)) {
            conn_state.sequence_mismatch_drop++;
            send_nack();
            continue;
        }

        store_frame(&frame);

        if (!swp_drain_in_order(out, out_capacity, out_len, meta, &sequence_done)) {
            send_nack();
            *out_len = 0;
            reset_sliding_window_receiver();
            return false;
        }

        send_sack_ack();

        if (sequence_done) {
            return (*out_len > 0u);
        }
    }

    reset_sliding_window_receiver();
    return false;
}

bool swp_transport_receive_frame_ex(uint8_t *out,
                                    size_t out_capacity,
                                    uint16_t *out_len,
                                    swp_rx_meta_t *meta,
                                    uint32_t timeout_ms) {
    if (!out || !out_len || out_capacity == 0u) {
        return false;
    }

    *out_len = 0;
    if (meta) {
        *meta = (swp_rx_meta_t){0};
    }

    if (swp_pop_next_in_order_frame(out, out_capacity, out_len, meta)) {
        return true;
    }

    const uint32_t start = millis();
    while ((millis() - start) < timeout_ms) {
        FrameType frame_type = FRAME_TYPE_UNKNOWN;
        Frame frame = {0};
        uint8_t ctrl_data[10] = {0};
        uint8_t ctrl_len = 0;
        const uint32_t elapsed = millis() - start;
        const uint32_t remaining_ms = timeout_ms - elapsed;

        if (!receive_any_frame_timed(&frame_type,
                                     &frame,
                                     ctrl_data,
                                     &ctrl_len,
                                     remaining_ms,
                                     100u)) {
            if (base_frame_index != next_frame_index) {
                check_timeouts_and_retransmit();
            }
            continue;
        }

        if (swp_process_receive_control(frame_type, ctrl_data, ctrl_len)) {
            continue;
        }

        if (!is_valid_encoding_type(frame.encoding_type)) {
            conn_state.sequence_mismatch_drop++;
            send_nack();
            continue;
        }

        store_frame(&frame);

        const bool have_in_order_frame = swp_pop_next_in_order_frame(out, out_capacity, out_len, meta);
        send_sack_ack();

        if (!have_in_order_frame) {
            continue;
        }

        return true;
    }

    return false;
}

bool swp_transport_receive_stream_ex(swp_transport_frame_visitor_t visitor,
                                     void *user_ctx,
                                     uint32_t timeout_ms,
                                     uint32_t complete_settle_ms) {
    if (visitor == NULL) {
        return false;
    }

    reset_sliding_window_receiver();

    const uint32_t start = millis();
    bool completion_seen = false;
    uint32_t last_completion_activity_ms = 0u;
    uint8_t frame_buf[MAX_DATA_SIZE] = {0};

    for (;;) {
        const uint32_t now = millis();
        if (!completion_seen) {
            if ((now - start) >= timeout_ms) {
                reset_sliding_window_receiver();
                return false;
            }
        } else if ((now - last_completion_activity_ms) >= complete_settle_ms) {
            return true;
        }

        FrameType frame_type = FRAME_TYPE_UNKNOWN;
        Frame frame = {0};
        uint8_t ctrl_data[10] = {0};
        uint8_t ctrl_len = 0;
        const uint32_t remaining_ms = completion_seen
            ? 100u
            : (timeout_ms - (now - start));

        if (!receive_any_frame_timed(&frame_type,
                                     &frame,
                                     ctrl_data,
                                     &ctrl_len,
                                     remaining_ms,
                                     100u)) {
            if (base_frame_index != next_frame_index) {
                check_timeouts_and_retransmit();
            }
            continue;
        }

        if (completion_seen) {
            last_completion_activity_ms = millis();
        }

        if (swp_process_receive_control(frame_type, ctrl_data, ctrl_len)) {
            continue;
        }

        if (!is_valid_encoding_type(frame.encoding_type)) {
            conn_state.sequence_mismatch_drop++;
            send_nack();
            continue;
        }

        store_frame(&frame);

        uint16_t frame_len = 0;
        swp_rx_meta_t meta = {0};
        bool emitted_frame = false;
        bool stream_complete = false;
        while (swp_pop_next_in_order_frame(frame_buf,
                                           sizeof(frame_buf),
                                           &frame_len,
                                           &meta)) {
            emitted_frame = true;
            if (!visitor(frame_buf, frame_len, &meta, &stream_complete, user_ctx)) {
                reset_sliding_window_receiver();
                return false;
            }
            if (stream_complete) {
                completion_seen = true;
                last_completion_activity_ms = millis();
            }
        }

        send_sack_ack();

        if (completion_seen && complete_settle_ms == 0u) {
            return true;
        }

        if (!emitted_frame) {
            continue;
        }
    }
}
