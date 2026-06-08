#include "commands/command_common.hpp"

#include "stardome_flags.h"
#include "swp_bridge.h"

#include <iomanip>
#include <iostream>
#include <sstream>
#include <vector>

namespace stardome {

namespace {

constexpr uint8_t kFlagMask = 0xFE;
constexpr size_t kMaxResponseBytes = 65535u;

uint8_t normalize_flag(uint8_t flags) {
    return static_cast<uint8_t>(flags & kFlagMask);
}

} // namespace

bool is_stardome_error_flag(uint8_t received_flags) {
    switch (normalize_flag(received_flags)) {
        case FLAG_SIGN_ERROR:
        case FLAG_STARDOME_PROOF_ERROR:
        case FLAG_STARDOME_DATA_ERROR:
        case FLAG_STARDOME_STATUS_ERROR:
        case FLAG_STARDOME_ID_ERROR:
        case FLAG_STARDOME_OFF_ERROR:
        case FLAG_STARDOME_LOWMODE_ERROR:
        case FLAG_STARDOME_HIGHMODE_ERROR:
            return true;
        default:
            return false;
    }
}

std::string format_flag_hex(uint8_t flag) {
    std::ostringstream oss;
    oss << "0x" << std::uppercase << std::hex << std::setfill('0') << std::setw(2)
        << static_cast<unsigned>(flag);
    return oss.str();
}

FrameClass classify_stardome_response_flag(uint8_t received_flags, uint8_t expected_base_flag) {
    const uint8_t normalized_received = normalize_flag(received_flags);
    const uint8_t normalized_expected = normalize_flag(expected_base_flag);

    if (normalized_received == normalized_expected) {
        return FrameClass::Expected;
    }
    if (is_stardome_error_flag(normalized_received)) {
        return FrameClass::Error;
    }
    return FrameClass::Unexpected;
}

std::string bytes_to_hex(const std::vector<uint8_t>& data) {
    std::ostringstream oss;
    oss << std::hex;
    for (uint8_t b : data) {
        if (b < 0x10) {
            oss << '0';
        }
        oss << static_cast<unsigned int>(b);
    }
    return oss.str();
}

bool send_request_and_receive(const AppConfig& cfg,
                              uint8_t flag,
                              std::vector<uint8_t>& response,
                              uint32_t timeout_ms) {
    return send_request_and_receive_ex(cfg, flag, response, nullptr, timeout_ms);
}

bool send_request_and_receive_ex(const AppConfig& cfg,
                                 uint8_t flag,
                                 std::vector<uint8_t>& response,
                                 swp_rx_meta_t* response_meta,
                                 uint32_t timeout_ms) {
    return send_payload_and_receive_ex(cfg, flag, nullptr, 0, response, response_meta, timeout_ms);
}

bool send_payload_and_receive_ex(const AppConfig& cfg,
                                 uint8_t flag,
                                 const uint8_t* payload,
                                 uint32_t payload_len,
                                 std::vector<uint8_t>& response,
                                 swp_rx_meta_t* response_meta,
                                 uint32_t timeout_ms) {
    response.clear();
    if (response_meta) {
        *response_meta = swp_rx_meta_t{};
    }

    std::string transport_error;
    if (!configure_transport_for_command(cfg, transport_error)) {
        std::cerr << transport_error << "\n";
        return false;
    }

    if (!swp_transport_open(cfg.port.c_str(), cfg.baud)) {
        std::cerr << "Failed to open serial port: " << cfg.port << "\n";
        return false;
    }

    const bool sent = swp_transport_send(payload,
                                         payload_len,
                                         static_cast<uint8_t>(flag | FLAG_LAST_FRAME),
                                         ENCODING_BINARY);
    if (!sent) {
        std::cerr << "Failed to send request\n";
        swp_transport_close();
        return false;
    }

    std::vector<uint8_t> buffer(kMaxResponseBytes, 0u);
    uint16_t response_len = 0;
    const bool received = swp_transport_receive_ex(buffer.data(),
                                                   buffer.size(),
                                                   &response_len,
                                                   response_meta,
                                                   timeout_ms);
    if (!received) {
        swp_transport_close();
        return false;
    }

    response.assign(buffer.begin(), buffer.begin() + response_len);
    swp_transport_close();
    return true;
}

bool configure_transport_for_command(const AppConfig& cfg, std::string& error) {
    if (swp_transport_configure_malform(cfg.malform_frame_count, cfg.malform_kind.c_str())) {
        return true;
    }

    error = "Invalid --malform-kind: " + cfg.malform_kind;
    return false;
}

int run_simple_request(const AppConfig& cfg, uint8_t flag, const char* label) {
    std::vector<uint8_t> response;
    if (!send_request_and_receive(cfg, flag, response, 5000)) {
        std::cerr << "Timeout waiting for " << label << " response\n";
        return 1;
    }

    std::cout << label << " response: " << response.size() << " bytes\n";
    return 0;
}

} // namespace stardome
