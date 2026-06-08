#include "app_config.hpp"

#include <cstdlib>

namespace stardome {

AppConfig default_config() {
    return AppConfig{};
}

void apply_env_overrides(AppConfig& cfg) {
    if (const char* scheme = std::getenv("STARDOME_SCHEME")) {
        cfg.scheme = scheme;
    }
    if (const char* port = std::getenv("STARDOME_PORT")) {
        cfg.port = port;
    }
    if (const char* baud = std::getenv("STARDOME_BAUD")) {
        cfg.baud = std::atoi(baud);
    }
}

} // namespace stardome
