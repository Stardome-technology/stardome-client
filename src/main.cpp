#include "app_config.hpp"
#include "command_router.hpp"

#include <iostream>

namespace stardome {
bool parse_options(AppConfig& cfg, int argc, char** argv, int& first_cmd_index);
void print_usage();
} // namespace stardome

int main(int argc, char** argv) {
    auto cfg = stardome::default_config();

    int cmd_index = 1;
    if (!stardome::parse_options(cfg, argc, argv, cmd_index)) {
        stardome::print_usage();
        return 2;
    }

    stardome::load_env_file(cfg.env_file);
    stardome::apply_env_overrides(cfg);

    cmd_index = 1;
    if (!stardome::parse_options(cfg, argc, argv, cmd_index)) {
        stardome::print_usage();
        return 2;
    }

    if (cmd_index >= argc || std::string(argv[cmd_index]) == "--help" || std::string(argv[cmd_index]) == "-h") {
        stardome::print_usage();
        return 0;
    }

    if (cfg.verbose) {
        std::cout << "Using scheme=" << cfg.scheme << " port=" << cfg.port << " baud=" << cfg.baud << "\n";
    }

    return stardome::route_command(cfg, argc - cmd_index, argv + cmd_index);
}
