#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

bool stardome_xmss_verify_detached(const uint8_t* pk,
                                   size_t pk_len,
                                   const uint8_t* message,
                                   size_t message_len,
                                   const uint8_t* signature,
                                   size_t signature_len,
                                   char* error_buffer,
                                   size_t error_buffer_len);

#ifdef __cplusplus
}
#endif
