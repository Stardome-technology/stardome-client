#pragma once

#include <cstdint>
#include <string>

namespace stardome {

struct AppConfig {
    std::string port = "/dev/ttyUSB0";
    int baud = 115200;
    std::string scheme = "v1.0.0_0";
    std::string env_file = ".env";
    bool verbose = false;
    uint32_t malform_frame_count = 0;
    std::string malform_kind = "crc_payload";
};

AppConfig default_config();
void apply_env_overrides(AppConfig& cfg);
bool load_env_file(const std::string& path);

} // namespace stardome
