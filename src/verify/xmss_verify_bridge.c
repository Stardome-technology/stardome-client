#include "verify/xmss_verify_bridge.h"

#include "params.h"
#include "sha256.h"
#include "xmss.h"
#include "xmss_callbacks.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void set_error(char* buffer, size_t buffer_len, const char* message) {
    if (!buffer || buffer_len == 0) {
        return;
    }
    snprintf(buffer, buffer_len, "%s", message ? message : "unknown error");
}

static uint32_t be32_read(const uint8_t* p) {
    return ((uint32_t)p[0] << 24) |
           ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) |
           ((uint32_t)p[3]);
}

bool stardome_xmss_verify_detached(const uint8_t* pk,
                                   size_t pk_len,
                                   const uint8_t* message,
                                   size_t message_len,
                                   const uint8_t* signature,
                                   size_t signature_len,
                                   char* error_buffer,
                                   size_t error_buffer_len) {
    if (!pk || !message || !signature) {
        set_error(error_buffer, error_buffer_len, "null input buffer");
        return false;
    }

    if (pk_len < 4) {
        set_error(error_buffer, error_buffer_len, "public key too short");
        return false;
    }

    const uint32_t default_oid = 0x00000005u;
    uint32_t oid = be32_read(pk);

    xmss_params params;
    if (xmssmt_parse_oid(&params, oid) != 0) {
        oid = default_oid;
        if (xmssmt_parse_oid(&params, oid) != 0) {
            set_error(error_buffer, error_buffer_len, "unsupported XMSSMT OID");
            return false;
        }
    }

    const size_t expected_pk_with_oid = (size_t)XMSS_OID_LEN + (size_t)params.pk_bytes;
    const size_t expected_pk_without_oid = (size_t)params.pk_bytes;

    uint8_t* pk_norm = NULL;
    if (pk_len == expected_pk_with_oid) {
        pk_norm = (uint8_t*)malloc(expected_pk_with_oid);
        if (!pk_norm) {
            set_error(error_buffer, error_buffer_len, "memory allocation failed (pk)");
            return false;
        }
        memcpy(pk_norm, pk, expected_pk_with_oid);
        pk_norm[0] = (uint8_t)((oid >> 24) & 0xFF);
        pk_norm[1] = (uint8_t)((oid >> 16) & 0xFF);
        pk_norm[2] = (uint8_t)((oid >> 8) & 0xFF);
        pk_norm[3] = (uint8_t)(oid & 0xFF);
    } else if (pk_len == expected_pk_without_oid) {
        pk_norm = (uint8_t*)malloc(expected_pk_with_oid);
        if (!pk_norm) {
            set_error(error_buffer, error_buffer_len, "memory allocation failed (pk normalize)");
            return false;
        }
        pk_norm[0] = (uint8_t)((oid >> 24) & 0xFF);
        pk_norm[1] = (uint8_t)((oid >> 16) & 0xFF);
        pk_norm[2] = (uint8_t)((oid >> 8) & 0xFF);
        pk_norm[3] = (uint8_t)(oid & 0xFF);
        memcpy(pk_norm + XMSS_OID_LEN, pk, expected_pk_without_oid);
    } else {
        set_error(error_buffer, error_buffer_len, "public key length mismatch");
        return false;
    }

    const size_t expected_sig_len = (size_t)params.sig_bytes;
    if (signature_len != expected_sig_len) {
        free(pk_norm);
        set_error(error_buffer, error_buffer_len, "signature length mismatch");
        return false;
    }

    if (xmss_set_sha_cb(xmss_sha256_wrapper) != 0) {
        free(pk_norm);
        set_error(error_buffer, error_buffer_len, "failed to register SHA callback");
        return false;
    }

    const size_t sm_len = signature_len + message_len;
    uint8_t* signed_message = (uint8_t*)malloc(sm_len);
    uint8_t* recovered = (uint8_t*)malloc(sm_len > 0 ? sm_len : 1);
    if (!signed_message || !recovered) {
        free(pk_norm);
        free(signed_message);
        free(recovered);
        set_error(error_buffer, error_buffer_len, "memory allocation failed (verify)");
        return false;
    }

    memcpy(signed_message, signature, signature_len);
    if (message_len > 0) {
        memcpy(signed_message + signature_len, message, message_len);
    }

    unsigned long long recovered_len = 0;
    const int verify_rc = xmssmt_sign_open(recovered,
                                           &recovered_len,
                                           signed_message,
                                           (unsigned long long)sm_len,
                                           pk_norm);

    bool ok = false;
    if (verify_rc == 0 && recovered_len == (unsigned long long)message_len) {
        ok = (message_len == 0) || (memcmp(recovered, message, message_len) == 0);
    }

    if (!ok) {
        set_error(error_buffer, error_buffer_len, "XMSS verification failed");
    }

    free(pk_norm);
    free(signed_message);
    free(recovered);
    return ok;
}
