#include "app_config.hpp"

#include <cstdint>
#include <cstring>
#include <iostream>

namespace stardome {

bool parse_options(AppConfig& cfg, int argc, char** argv, int& first_cmd_index) {
    first_cmd_index = 1;
    while (first_cmd_index < argc) {
        const char* arg = argv[first_cmd_index];
        if (std::strcmp(arg, "--help") == 0 || std::strcmp(arg, "-h") == 0) {
            return true;
        }
        if (arg[0] != '-') {
            break;
        }

        auto need_value = [&](const char* name) -> const char* {
            if (first_cmd_index + 1 >= argc) {
                std::cerr << "Missing value for " << name << "\n";
                return nullptr;
            }
            return argv[++first_cmd_index];
        };

        if (std::strcmp(arg, "--port") == 0) {
            const char* value = need_value("--port");
            if (!value) {
                return false;
            }
            cfg.port = value;
        } else if (std::strcmp(arg, "--baud") == 0) {
            const char* value = need_value("--baud");
            if (!value) {
                return false;
            }
            cfg.baud = std::atoi(value);
        } else if (std::strcmp(arg, "--scheme") == 0) {
            const char* value = need_value("--scheme");
            if (!value) {
                return false;
            }
            cfg.scheme = value;
        } else if (std::strcmp(arg, "--env") == 0) {
            const char* value = need_value("--env");
            if (!value) {
                return false;
            }
            cfg.env_file = value;
        } else if (std::strcmp(arg, "--verbose") == 0) {
            cfg.verbose = true;
        } else if (std::strcmp(arg, "--malform-count") == 0) {
            const char* value = need_value("--malform-count");
            if (!value) {
                return false;
            }
            cfg.malform_frame_count = static_cast<uint32_t>(std::strtoul(value, nullptr, 10));
        } else if (std::strcmp(arg, "--malform-kind") == 0) {
            const char* value = need_value("--malform-kind");
            if (!value) {
                return false;
            }
            cfg.malform_kind = value;
        } else {
            std::cerr << "Unknown option: " << arg << "\n";
            return false;
        }

        ++first_cmd_index;
    }

    return true;
}

void print_usage() {
    std::cout
        << "stardome-client [options] <command> [command-args]\n\n"
        << "Options:\n"
        << "  --port <tty>          Serial port path (default /dev/ttyUSB0)\n"
        << "  --baud <rate>         Baud rate (default 115200)\n"
        << "  --scheme <name>       Override STARDOME_SCHEME\n"
        << "  --env <path>          .env file path (default .env)\n"
        << "  --verbose             Enable verbose logs\n"
        << "  --malform-count <n>   Inject malformed DATA frames into the next sent sequence\n"
        << "  --malform-kind <kind> Malformation kind: crc_payload | crc_header | token_bad | len_over | len_mismatch | seq_jump | encoding_invalid | truncate_tail | all\n\n"
        << "Commands:\n"
        << "  status | id | lowmode | highmode | off | proof | attestation | attestation-file | firmware | timestamp | bootlog | verify\n\n"
        << "Command help:\n"
        << "  stardome-client proof --help\n"
        << "  stardome-client attestation --help\n"
        << "  stardome-client attestation-file --help\n"
        << "  stardome-client id --help\n"
        << "  stardome-client lowmode --help\n"
        << "  stardome-client highmode --help\n"
        << "  stardome-client off --help\n"
        << "  stardome-client bootlog --help\n";
}

} // namespace stardome
