#include "commands/command_common.hpp"
#include "stardome_flags.h"
#include "swp_bridge.h"

#include <cstdint>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

namespace stardome {

namespace {

constexpr size_t kMaxFirmwareResponseBytes = 65535u;

std::vector<uint8_t> read_binary_file(const std::string& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in.is_open()) {
        return {};
    }
    return std::vector<uint8_t>(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
}

} // namespace

int run_firmware_command(const AppConfig& cfg, int argc, char** argv) {
    std::string file_path;
    uint32_t timeout_ms = 1200;

    for (int i = 0; i < argc; ++i) {
        const std::string arg = argv[i];
        if (arg == "--file" && i + 1 < argc) {
            file_path = argv[++i];
        } else if (arg == "--timeout-ms" && i + 1 < argc) {
            timeout_ms = static_cast<uint32_t>(std::strtoul(argv[++i], nullptr, 10));
        }
    }

    if (file_path.empty()) {
        std::cerr << "Missing required argument: --file <firmware.bin>\n";
        return 2;
    }

    const std::vector<uint8_t> payload = read_binary_file(file_path);
    if (payload.empty()) {
        std::cerr << "Failed to read firmware file (or file is empty): " << file_path << "\n";
        return 2;
    }

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
        std::cerr << "Failed to send firmware payload\n";
        swp_transport_close();
        return 2;
    }

    std::cout << "Sent firmware payload: " << payload.size() << " bytes\n";

    std::vector<uint8_t> response_buf(kMaxFirmwareResponseBytes, 0u);
    uint16_t response_len = 0;
    swp_rx_meta_t response_meta{};
    const bool got_response = swp_transport_receive_ex(response_buf.data(),
                                                       response_buf.size(),
                                                       &response_len,
                                                       &response_meta,
                                                       timeout_ms);
    swp_transport_close();

    if (got_response && response_len > 0) {
        const std::vector<uint8_t> response(response_buf.begin(), response_buf.begin() + response_len);
        const FrameClass frame_class = classify_stardome_response_flag(response_meta.flags, FLAG_STARDOME_DATA);
        if (frame_class == FrameClass::Error) {
            std::cerr << "Device reported firmware error (flags="
                      << format_flag_hex(response_meta.flags)
                      << "): " << bytes_to_hex(response) << "\n";
            return 5;
        }
        if (frame_class == FrameClass::Unexpected) {
            std::cerr << "Unexpected firmware response frame (flags="
                      << format_flag_hex(response_meta.flags)
                      << ", payload=" << response_len << " bytes)\n";
            return 1;
        }

        std::cout << "Received expected post-transfer response payload (" << response_len
                  << " bytes): " << bytes_to_hex(response) << "\n";
    } else {
        std::cout << "No explicit response expected; no payload received in wait window.\n";
    }

    return 0;
}

} // namespace stardome
