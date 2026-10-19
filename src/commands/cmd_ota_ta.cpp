#include "commands/command_common.hpp"
#include "stardome_flags.h"

#include <cstdint>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <vector>

namespace stardome {

namespace {

// Raw OTA-TA status bytes as space-separated lowercase hex (e.g. "03 03 03").
std::string bytes_to_hex_spaced(const std::vector<uint8_t>& data) {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (size_t i = 0; i < data.size(); ++i) {
        if (i != 0) {
            oss << ' ';
        }
        oss << std::setw(2) << static_cast<unsigned>(data[i]);
    }
    return oss.str();
}

} // namespace

int run_ota_ta_command(const AppConfig& cfg, int argc, char** argv) {
    (void)argc;
    (void)argv;

    std::vector<uint8_t> response;
    swp_rx_meta_t response_meta{};
    if (!send_request_and_receive_ex(cfg, FLAG_STARDOME_OTA_TA, response, &response_meta, 5000)) {
        std::cerr << "Timeout waiting for OTA-TA response\n";
        return 1;
    }

    const FrameClass frame_class = classify_stardome_response_flag(response_meta.flags, FLAG_STARDOME_OTA_TA_DATA);
    if (frame_class == FrameClass::Error) {
        std::cerr << "Device reported OTA-TA error (flags=" << format_flag_hex(response_meta.flags)
                  << "): " << bytes_to_hex(response) << "\n";
        return 1;
    }
    if (frame_class == FrameClass::Unexpected) {
        std::cerr << "Unexpected OTA-TA response frame (flags=" << format_flag_hex(response_meta.flags)
                  << ", payload=" << response.size() << " bytes)\n";
        return 1;
    }

    std::cout << bytes_to_hex_spaced(response) << "\n";
    return 0;
}

} // namespace stardome
