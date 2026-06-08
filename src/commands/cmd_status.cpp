#include "commands/command_common.hpp"
#include "stardome_flags.h"

#include "qcbor/qcbor_common.h"
#include "qcbor/qcbor_spiffy_decode.h"

#include <iomanip>
#include <iostream>
#include <string>
#include <vector>

namespace stardome {

namespace {

bool decode_status_response_uint(const std::vector<uint8_t>& payload,
                                 uint64_t& status,
                                 std::string& error) {
    if (payload.empty()) {
        error = "empty payload";
        return false;
    }

    QCBORDecodeContext decode_ctx;
    UsefulBufC encoded{payload.data(), payload.size()};
    QCBORDecode_Init(&decode_ctx, encoded, QCBOR_DECODE_MODE_NORMAL);

    QCBORItem item{};
    QCBORDecode_GetNext(&decode_ctx, &item);

    const QCBORError finish_error = QCBORDecode_Finish(&decode_ctx);
    if (finish_error != QCBOR_SUCCESS) {
        error = qcbor_err_to_str(finish_error);
        return false;
    }

    if (item.uDataType == QCBOR_TYPE_UINT64) {
        status = item.val.uint64;
        return true;
    }

    if (item.uDataType == QCBOR_TYPE_INT64) {
        if (item.val.int64 < 0) {
            error = "status response must be non-negative";
            return false;
        }
        status = static_cast<uint64_t>(item.val.int64);
        return true;
    }

    error = "status response must be CBOR integer";
    return false;
}

const char* status_to_text(uint64_t status) {
    switch (status) {
        case 1u:
            return "IDLE";
        case 2u:
            return "BUSY";
        case 3u:
            return "BOOTING";
        case 4u:
            return "ERROR";
        default:
            return "UNKNOWN";
    }
}

} // namespace

int run_status_command(const AppConfig& cfg, int argc, char** argv) {
    (void)argc;
    (void)argv;

    std::vector<uint8_t> response;
    swp_rx_meta_t response_meta{};
    if (!send_request_and_receive_ex(cfg, FLAG_STARDOME_STATUS, response, &response_meta, 5000)) {
        std::cerr << "Timeout waiting for status response\n";
        return 1;
    }

    const FrameClass frame_class = classify_stardome_response_flag(response_meta.flags, FLAG_STARDOME_STATUS_DATA);
    if (frame_class == FrameClass::Error) {
        std::cerr << "Device reported status error (flags=" << format_flag_hex(response_meta.flags)
                  << "): " << bytes_to_hex(response) << "\n";
        return 1;
    }
    if (frame_class == FrameClass::Unexpected) {
        std::cerr << "Unexpected status response frame (flags=" << format_flag_hex(response_meta.flags)
                  << ", payload=" << response.size() << " bytes)\n";
        return 1;
    }

    uint64_t status = 0u;
    std::string decode_error;

    if (!decode_status_response_uint(response, status, decode_error)) {
        std::cerr << "Failed to decode status response: " << decode_error << "\n";
        return 1;
    }

    std::cout << "Status: 0x" << std::hex << std::uppercase << std::setfill('0')
              << std::setw(2) << status << std::dec << " (" << status_to_text(status)
              << ")\n";
    return 0;
}

} // namespace stardome
