#include "commands/command_common.hpp"
#include "stardome_flags.h"

#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <string>
#include <vector>

namespace stardome {

namespace {

int run_mode_command(const AppConfig& cfg,
                     int argc,
                     char** argv,
                     uint8_t mode_flag,
                     const char* mode_name) {
    uint32_t wait_ms = 5000;

    for (int i = 0; i < argc; ++i) {
        const std::string arg = argv[i];
        if (arg == "--help" || arg == "-h") {
            std::cout << "Usage: stardome-client [options] " << mode_name << " [--wait-ms N]\n";
            return 0;
        }
        if (arg == "--wait-ms" && i + 1 < argc) {
            wait_ms = static_cast<uint32_t>(std::strtoul(argv[++i], nullptr, 10));
            continue;
        }

        std::cerr << "Unknown option for " << mode_name << ": " << arg << "\n";
        return 2;
    }

    std::vector<uint8_t> response;
    swp_rx_meta_t response_meta{};
    if (!send_request_and_receive_ex(cfg, mode_flag, response, &response_meta, wait_ms)) {
        std::cerr << "Timeout waiting for " << mode_name << " response\n";
        return 1;
    }

    const FrameClass frame_class = classify_stardome_response_flag(response_meta.flags, mode_flag);
    if (frame_class == FrameClass::Error) {
        std::cerr << "Device reported " << mode_name << " error (flags="
                  << format_flag_hex(response_meta.flags)
                  << "): " << bytes_to_hex(response) << "\n";
        return 1;
    }
    if (frame_class == FrameClass::Unexpected) {
        std::cerr << "Unexpected " << mode_name << " response frame (flags="
                  << format_flag_hex(response_meta.flags)
                  << ", payload=" << response.size() << " bytes)\n";
        return 1;
    }

    std::cout << mode_name << " response: " << response.size() << " bytes\n";
    return 0;
}

} // namespace

int run_lowmode_command(const AppConfig& cfg, int argc, char** argv) {
    return run_mode_command(cfg, argc, argv, FLAG_STARDOME_LOWMODE, "lowmode");
}

int run_highmode_command(const AppConfig& cfg, int argc, char** argv) {
    return run_mode_command(cfg, argc, argv, FLAG_STARDOME_HIGHMODE, "highmode");
}

} // namespace stardome
