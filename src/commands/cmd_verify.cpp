#include "commands/command_common.hpp"
#include "verify/stardome_attestation_verify.hpp"

#include <fstream>
#include <iostream>
#include <string>
#include <vector>

namespace stardome {

namespace {

std::vector<uint8_t> read_binary_file(const std::string& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in.is_open()) {
        return {};
    }
    return std::vector<uint8_t>(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
}

} // namespace

int run_verify_command(const AppConfig& cfg, int argc, char** argv) {
    std::string tree_path = "stardome_tree.bin";
    std::string attestation_path = "stardome_attestation.bin";

    for (int i = 0; i < argc; ++i) {
        const std::string arg = argv[i];
        if (arg == "--tree" && i + 1 < argc) {
            tree_path = argv[++i];
        } else if (arg == "--attestation" && i + 1 < argc) {
            attestation_path = argv[++i];
        }
    }

    const std::vector<uint8_t> tree_cbor = read_binary_file(tree_path);
    if (tree_cbor.empty()) {
        std::cerr << "Failed to read tree file: " << tree_path << "\n";
        return 2;
    }

    const std::vector<uint8_t> attestation_cbor = read_binary_file(attestation_path);
    if (attestation_cbor.empty()) {
        std::cerr << "Failed to read attestation file: " << attestation_path << "\n";
        return 2;
    }

    std::string failure_reason;
    AttestationVerificationOptions options;
    options.scheme_version = cfg.scheme;
    const bool ok = verify_attestation_bundle_verbose(tree_cbor,
                                                      attestation_cbor,
                                                      options,
                                                      std::cout,
                                                      failure_reason);
    return ok ? 0 : 1;
}

} // namespace stardome
