#include "commands/command_common.hpp"
#include "stardome_flags.h"
#include "swp_bridge.h"

#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <ctime>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

namespace stardome {

namespace {

constexpr size_t kMaxTimestampResponseBytes = 65535u;

constexpr int64_t GPS_EPOCH_UNIX = 315964800;
constexpr int64_t SECONDS_PER_GPS_WEEK = 604800;

bool parse_iso_utc(const std::string& value, std::time_t& unix_time_out) {
    std::tm tm{};
    std::istringstream iss(value);
    iss >> std::get_time(&tm, "%Y-%m-%dT%H:%M:%SZ");
    if (iss.fail()) {
        return false;
    }

    tm.tm_isdst = 0;
    unix_time_out = timegm(&tm);
    return unix_time_out >= 0;
}

bool validate_gps_values(uint64_t gps_week, uint64_t tow_seconds) {
    return gps_week <= 65535u && tow_seconds <= 604799u;
}

bool utc_to_gps(std::time_t unix_seconds,
                int leap_seconds,
                uint64_t& gps_week_out,
                uint64_t& tow_seconds_out) {
    const int64_t gps_seconds = static_cast<int64_t>(unix_seconds) + static_cast<int64_t>(leap_seconds) - GPS_EPOCH_UNIX;
    if (gps_seconds < 0) {
        return false;
    }

    gps_week_out = static_cast<uint64_t>(gps_seconds / SECONDS_PER_GPS_WEEK);
    tow_seconds_out = static_cast<uint64_t>(gps_seconds % SECONDS_PER_GPS_WEEK);
    return validate_gps_values(gps_week_out, tow_seconds_out);
}

const char* decode_stardome_data_error_reason(uint8_t code) {
    switch (code) {
        // Current policy: FLAG_STARDOME_DATA_ERROR is ingress/classification only.
        case 0x01: return "empty payload";
        case 0x02: return "staged source read failure";
        case 0x0B: return "unsupported/unknown STARDOME_DATA payload type";
        // Legacy/older firmware values (OTA-only path).
        case 0x03: return "file open failed";
        case 0x04: return "descriptor invalid/not found (payload is not firmware image descriptor)";
        case 0x05: return "size mismatch/out of range";
        case 0x06: return "flash erase failed";
        case 0x07: return "flash write failed";
        case 0x08: return "verify failed";
        case 0x09: return "vector sanity failed";
        case 0x0A: return "bank swap failed";
        default: return nullptr;
    }
}

} // namespace

int run_timestamp_command(const AppConfig& cfg, int argc, char** argv) {
    std::string iso_utc;
    bool has_gps_week = false;
    bool has_tow_seconds = false;
    uint64_t gps_week = 0;
    uint64_t tow_seconds = 0;
    int leap_seconds = 18;
    uint32_t wait_ms = 1200;

    for (int i = 0; i < argc; ++i) {
        const std::string arg = argv[i];
        if (arg == "--iso-utc" && i + 1 < argc) {
            iso_utc = argv[++i];
        } else if (arg == "--gps-week" && i + 1 < argc) {
            gps_week = static_cast<uint64_t>(std::strtoull(argv[++i], nullptr, 10));
            has_gps_week = true;
        } else if (arg == "--tow-seconds" && i + 1 < argc) {
            tow_seconds = static_cast<uint64_t>(std::strtoull(argv[++i], nullptr, 10));
            has_tow_seconds = true;
        } else if (arg == "--leap-seconds" && i + 1 < argc) {
            leap_seconds = std::atoi(argv[++i]);
        } else if (arg == "--wait-ms" && i + 1 < argc) {
            wait_ms = static_cast<uint32_t>(std::strtoul(argv[++i], nullptr, 10));
        }
    }

    if (has_gps_week != has_tow_seconds) {
        std::cerr << "--gps-week and --tow-seconds must be provided together\n";
        return 2;
    }

    // Precedence contract (kept in sync with Python client):
    // - If --gps-week and --tow-seconds are provided, they are used directly.
    // - Otherwise, use UTC path (--iso-utc if provided, else current UTC time)
    //   and convert to GPS week/TOW.
    if (has_gps_week && !iso_utc.empty()) {
        std::cout << "INFO: Using explicit GPS week/TOW override; --iso-utc is ignored.\n";
    }

    if (!has_gps_week) {
        std::time_t unix_now = 0;
        if (!iso_utc.empty()) {
            if (!parse_iso_utc(iso_utc, unix_now)) {
                std::cerr << "Invalid --iso-utc format, expected YYYY-MM-DDTHH:MM:SSZ\n";
                return 2;
            }
        } else {
            unix_now = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
        }

        if (!utc_to_gps(unix_now, leap_seconds, gps_week, tow_seconds)) {
            std::cerr << "UTC to GPS conversion failed or value out of range\n";
            return 2;
        }
    }

    if (!validate_gps_values(gps_week, tow_seconds)) {
        std::cerr << "gps_week must be 0..65535 and tow_seconds must be 0..604799\n";
        return 2;
    }

    std::vector<uint8_t> payload(6, 0);
    payload[0] = static_cast<uint8_t>(gps_week & 0xFFu);
    payload[1] = static_cast<uint8_t>((gps_week >> 8) & 0xFFu);
    payload[2] = static_cast<uint8_t>(tow_seconds & 0xFFu);
    payload[3] = static_cast<uint8_t>((tow_seconds >> 8) & 0xFFu);
    payload[4] = static_cast<uint8_t>((tow_seconds >> 16) & 0xFFu);
    payload[5] = static_cast<uint8_t>((tow_seconds >> 24) & 0xFFu);

    std::cout << "gps_week: " << gps_week << "\n";
    std::cout << "tow_seconds: " << tow_seconds << "\n";
    std::cout << "payload hex: " << bytes_to_hex(payload) << "\n";

    std::string transport_error;
    if (!configure_transport_for_command(cfg, transport_error)) {
        std::cerr << transport_error << "\n";
        return 2;
    }

    if (!swp_transport_open(cfg.port.c_str(), cfg.baud)) {
        std::cerr << "Failed to open serial port: " << cfg.port << "\n";
        return 2;
    }

    const bool sent = swp_transport_send(payload.data(),
                                         static_cast<uint32_t>(payload.size()),
                                         static_cast<uint8_t>(FLAG_STARDOME_DATA | FLAG_LAST_FRAME),
                                         ENCODING_BINARY);
    if (!sent) {
        std::cerr << "Failed to send timestamp payload\n";
        swp_transport_close();
        return 2;
    }

    std::vector<uint8_t> response_buf(kMaxTimestampResponseBytes, 0u);
    uint16_t response_len = 0;
    swp_rx_meta_t response_meta{};
    const bool got_response = swp_transport_receive_ex(response_buf.data(),
                                                       response_buf.size(),
                                                       &response_len,
                                                       &response_meta,
                                                       wait_ms);
    swp_transport_close();

    if (got_response && response_len > 0) {
        const std::vector<uint8_t> response(response_buf.begin(), response_buf.begin() + response_len);
        const FrameClass frame_class = classify_stardome_response_flag(response_meta.flags, FLAG_STARDOME_DATA);
        if (frame_class == FrameClass::Error) {
            if (!response.empty()) {
                const uint8_t err_code = response[0];
                const char* reason = decode_stardome_data_error_reason(err_code);
                std::cerr << "Device reported timestamp error (flags="
                          << format_flag_hex(response_meta.flags)
                          << ", code=0x" << std::uppercase << std::hex << std::setw(2) << std::setfill('0')
                          << static_cast<unsigned>(err_code) << std::dec;
                if (reason != nullptr) {
                    std::cerr << ", reason=" << reason;
                }
                std::cerr << "): " << bytes_to_hex(response) << "\n";
                if (err_code == 0x04u) {
                    std::cerr << "Hint: this indicates legacy OTA-only STARDOME_DATA routing; "
                              << "timestamp payloads are being treated as firmware blobs.\n";
                }
                return 1;
            }
            std::cerr << "Device reported timestamp error (flags="
                      << format_flag_hex(response_meta.flags)
                      << "): " << bytes_to_hex(response) << "\n";
            return 1;
        }
        if (frame_class == FrameClass::Unexpected) {
            std::cerr << "Unexpected timestamp response frame (flags="
                      << format_flag_hex(response_meta.flags)
                      << ", payload=" << response_len << " bytes)\n";
            return 1;
        }
        std::cout << "Received expected timestamp response payload (" << response_len
                  << " bytes): " << bytes_to_hex(response) << "\n";
    } else {
        std::cout << "No explicit response expected; no payload received in wait window.\n";
    }

    return 0;
}

} // namespace stardome
