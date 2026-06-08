#pragma once

#include <cstdint>
#include <iosfwd>
#include <string>
#include <vector>

namespace stardome {

struct AttestationVerificationOptions {
    std::string scheme_version;
    const std::vector<uint8_t>* payload_cbor = nullptr;
};

bool verify_attestation_bundle_verbose(const std::vector<uint8_t>& tree_cbor,
                                       const std::vector<uint8_t>& attestation_cbor,
                                       const AttestationVerificationOptions& options,
                                       std::ostream& out,
                                       std::string& failure_reason);

std::string normalize_scheme_version_label(const std::string& scheme);

} // namespace stardome