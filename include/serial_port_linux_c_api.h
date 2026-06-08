#pragma once

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

bool serial_open_port(const char* path, int baudrate);
void serial_close_port(void);
bool serial_send_byte(uint8_t byte);
uint8_t serial_receive_byte(void);
bool serial_rx_available(void);
void serial_flush_tx(void);
uint32_t serial_millis_now(void);

#ifdef __cplusplus
}
#endif
