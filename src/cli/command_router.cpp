#include "command_router.hpp"

#include "commands/command_common.hpp"

#include <iostream>
#include <string>

namespace stardome {

int route_command(const AppConfig& cfg, int argc, char** argv) {
    if (argc <= 0) {
        std::cerr << "Missing command\n";
        return 2;
    }

    const std::string command = argv[0];
    const int sub_argc = argc - 1;
    char** sub_argv = argv + 1;

    if (command == "status") return run_status_command(cfg, sub_argc, sub_argv);
    if (command == "id") return run_id_command(cfg, sub_argc, sub_argv);
    if (command == "lowmode") return run_lowmode_command(cfg, sub_argc, sub_argv);
    if (command == "highmode") return run_highmode_command(cfg, sub_argc, sub_argv);
    if (command == "off") return run_off_command(cfg, sub_argc, sub_argv);
    if (command == "proof") return run_proof_command(cfg, sub_argc, sub_argv);
    if (command == "attestation") return run_attestation_command(cfg, sub_argc, sub_argv);
    if (command == "attestation-file") return run_attestation_file_command(cfg, sub_argc, sub_argv);
    if (command == "firmware") return run_firmware_command(cfg, sub_argc, sub_argv);
    if (command == "timestamp") return run_timestamp_command(cfg, sub_argc, sub_argv);
    if (command == "bootlog") return run_bootlog_command(cfg, sub_argc, sub_argv);
    if (command == "verify") return run_verify_command(cfg, sub_argc, sub_argv);

    std::cerr << "Unknown command: " << command << "\n";
    return 2;
}

} // namespace stardome
