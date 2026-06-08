#include "verify/stardome_attestation_verify.hpp"

#include "qcbor/qcbor_common.h"
#include "qcbor/qcbor_decode.h"
#include "qcbor/qcbor_spiffy_decode.h"
#include "verify/xmss_verify_bridge.h"

#ifdef __cplusplus
extern "C" {
#endif
#include "merkle_tree_cbor.h"
#include "sha256.h"
#ifdef __cplusplus
}
#endif

#include <algorithm>
#include <array>
#include <cstdint>
#include <iomanip>
#include <ostream>
#include <sstream>
#include <string>
#include <vector>

namespace stardome {

namespace {

enum class ValidationFormat {
    HexOnly,
    Ascii,
    U64Be,
    U32AndI32Be,
    EpochRecord,
};

struct ValidationDescriptor {
    const char* label;
    ValidationFormat format;
};

struct SecurityFlags {
    bool use_double_leaf_hash = false;
    bool use_depth_prefix = false;
    bool use_node_prefix = false;
    bool present = false;
};

struct TreeBundle {
    std::vector<std::vector<uint8_t>> nodes;
    uint64_t depth = 0;
    bool has_depth = false;
    SecurityFlags security_flags{};
};

struct AttestationBundle {
    std::vector<uint8_t> pk_root;
    std::vector<uint8_t> merkle_root;
    std::vector<uint8_t> xmss_sig;
    std::vector<std::vector<uint8_t>> leaf_hashes;
    std::vector<std::vector<uint8_t>> host_keys;
    std::vector<std::vector<uint8_t>> validation_data;
};

std::string hex_bytes(const std::vector<uint8_t>& data) {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (uint8_t byte : data) {
        oss << std::setw(2) << static_cast<unsigned>(byte);
    }
    return oss.str();
}

std::string hex_prefix(const std::vector<uint8_t>& data, size_t count) {
    const size_t limit = std::min(count, data.size());
    std::vector<uint8_t> prefix(data.begin(), data.begin() + static_cast<std::ptrdiff_t>(limit));
    return hex_bytes(prefix);
}

std::vector<uint8_t> useful_buf_to_vector(UsefulBufC bytes) {
    const auto* begin = reinterpret_cast<const uint8_t*>(bytes.ptr);
    return std::vector<uint8_t>(begin, begin + bytes.len);
}

std::vector<uint8_t> sha256_bytes(const std::vector<uint8_t>& data) {
    std::vector<uint8_t> digest(32u, 0u);
    sha256_ctx ctx{};
    sha256_init(&ctx);
    if (!data.empty()) {
        sha256_update(&ctx, data.data(), data.size());
    }
    sha256_final(&ctx, digest.data());
    return digest;
}

SecurityFlags security_flags_from_tree(const secure_merkle_tree_t* tree) {
    SecurityFlags flags{};
    if (tree == nullptr || !tree->security_enabled || tree->algo == nullptr) {
        return flags;
    }

    flags.use_double_leaf_hash = tree->algo->use_double_leaf_hash;
    flags.use_depth_prefix = tree->algo->use_depth_prefix;
    flags.use_node_prefix = tree->algo->use_node_prefix;
    flags.present = true;
    return flags;
}

uint64_t read_be64(const std::vector<uint8_t>& raw) {
    uint64_t value = 0;
    for (uint8_t byte : raw) {
        value = (value << 8) | byte;
    }
    return value;
}

uint32_t read_be32(const std::vector<uint8_t>& raw) {
    uint32_t value = 0;
    for (uint8_t byte : raw) {
        value = (value << 8) | byte;
    }
    return value;
}

bool is_printable_ascii(const std::vector<uint8_t>& raw) {
    return std::all_of(raw.begin(), raw.end(), [](uint8_t byte) {
        return byte >= 0x20u && byte <= 0x7Eu;
    });
}

std::string ascii_bytes(const std::vector<uint8_t>& raw) {
    return std::string(raw.begin(), raw.end());
}

ValidationDescriptor describe_validation_data(const std::string& scheme_version, size_t index) {
    static constexpr std::array<ValidationDescriptor, 4> kCommon = {{
        {"leaf_id", ValidationFormat::HexOnly},
        {"leaf_timestamp", ValidationFormat::Ascii},
        {"leaf_xmss_pk", ValidationFormat::HexOnly},
        {"leaf_epoch", ValidationFormat::EpochRecord},
    }};

    if (index < kCommon.size()) {
        return kCommon[index];
    }

    if (scheme_version == "1.0.0_1") {
        static constexpr std::array<ValidationDescriptor, 10> kSatelliteClock = {{
            {"leaf_clock_timestamp[0]", ValidationFormat::U64Be},
            {"leaf_clock_counter[0]", ValidationFormat::U32AndI32Be},
            {"leaf_clock_counter[1]", ValidationFormat::U32AndI32Be},
            {"leaf_clock_drift[0]", ValidationFormat::U32AndI32Be},
            {"leaf_clock_drift[1]", ValidationFormat::U32AndI32Be},
            {"leaf_clock_timestamp[1]", ValidationFormat::U64Be},
            {"leaf_clock_counter[2]", ValidationFormat::U32AndI32Be},
            {"leaf_clock_counter[3]", ValidationFormat::U32AndI32Be},
            {"leaf_clock_drift[2]", ValidationFormat::U32AndI32Be},
            {"leaf_clock_drift[3]", ValidationFormat::U32AndI32Be},
        }};

        const size_t clock_index = index - kCommon.size();
        if (clock_index < kSatelliteClock.size()) {
            return kSatelliteClock[clock_index];
        }
    }

    return {"validation_data", ValidationFormat::HexOnly};
}

std::vector<uint8_t> hash_leaf(const std::vector<uint8_t>& data,
                               uint64_t depth,
                               const SecurityFlags& security_flags) {
    std::vector<uint8_t> buffer;
    if (security_flags.use_node_prefix) {
        buffer.push_back(0x00u);
    }
    if (security_flags.use_depth_prefix) {
        buffer.push_back(static_cast<uint8_t>(depth & 0xFFu));
    }
    buffer.insert(buffer.end(), data.begin(), data.end());

    std::vector<uint8_t> digest = sha256_bytes(buffer);
    if (security_flags.use_double_leaf_hash) {
        digest = sha256_bytes(digest);
    }
    return digest;
}

bool decode_bytes_array(UsefulBufC encoded_array,
                        std::vector<std::vector<uint8_t>>& out,
                        std::string& error) {
    QCBORDecodeContext array_ctx;
    QCBORDecode_Init(&array_ctx, encoded_array, QCBOR_DECODE_MODE_NORMAL);

    QCBORItem entered_array{};
    QCBORDecode_EnterArray(&array_ctx, &entered_array);
    if (QCBORDecode_GetError(&array_ctx) != QCBOR_SUCCESS) {
        error = qcbor_err_to_str(QCBORDecode_GetError(&array_ctx));
        return false;
    }
    if (entered_array.uDataType != QCBOR_TYPE_ARRAY || entered_array.val.uCount == UINT16_MAX) {
        error = "expected definite-length array";
        return false;
    }

    out.clear();
    out.reserve(entered_array.val.uCount);
    for (uint16_t i = 0; i < entered_array.val.uCount; ++i) {
        QCBORItem item{};
        QCBORDecode_VGetNext(&array_ctx, &item);
        if (QCBORDecode_GetError(&array_ctx) != QCBOR_SUCCESS) {
            error = qcbor_err_to_str(QCBORDecode_GetError(&array_ctx));
            return false;
        }
        if (item.uDataType != QCBOR_TYPE_BYTE_STRING) {
            error = "array contains non-byte-string item";
            return false;
        }
        out.push_back(useful_buf_to_vector(item.val.string));
    }

    QCBORDecode_ExitArray(&array_ctx);
    const QCBORError finish_error = QCBORDecode_Finish(&array_ctx);
    if (finish_error != QCBOR_SUCCESS) {
        error = qcbor_err_to_str(finish_error);
        return false;
    }

    return true;
}

bool decode_optional_bytes_array_from_map(const std::vector<uint8_t>& payload,
                                          int64_t map_key,
                                          std::vector<std::vector<uint8_t>>& out,
                                          bool required,
                                          std::string& error) {
    QCBORDecodeContext decode_ctx;
    UsefulBufC encoded{payload.data(), payload.size()};
    QCBORDecode_Init(&decode_ctx, encoded, QCBOR_DECODE_MODE_NORMAL);

    QCBORItem map_item{};
    QCBORDecode_EnterMap(&decode_ctx, &map_item);
    if (QCBORDecode_GetError(&decode_ctx) != QCBOR_SUCCESS) {
        error = qcbor_err_to_str(QCBORDecode_GetError(&decode_ctx));
        return false;
    }
    if (map_item.uDataType != QCBOR_TYPE_MAP) {
        error = "expected CBOR map";
        return false;
    }

    QCBORItem array_item{};
    UsefulBufC encoded_array{};
    QCBORDecode_GetArrayFromMapN(&decode_ctx, map_key, &array_item, &encoded_array);
    QCBORDecode_ExitMap(&decode_ctx);
    const QCBORError finish_error = QCBORDecode_Finish(&decode_ctx);
    if (finish_error == QCBOR_ERR_LABEL_NOT_FOUND && !required) {
        out.clear();
        return true;
    }
    if (finish_error != QCBOR_SUCCESS) {
        error = qcbor_err_to_str(finish_error);
        return false;
    }

    return decode_bytes_array(encoded_array, out, error);
}

bool decode_tree_bundle(const std::vector<uint8_t>& tree_cbor,
                        TreeBundle& tree,
                        std::string& error) {
    secure_merkle_tree_t* decoded = secure_merkle_tree_decode(tree_cbor.data(), tree_cbor.size());
    if (decoded == nullptr) {
        error = "failed to decode secure merkle tree";
        return false;
    }

    tree.nodes.clear();
    tree.nodes.reserve(decoded->nodes_count);
    for (size_t i = 0; i < decoded->nodes_count; ++i) {
        const uint8_t* node_begin = decoded->nodes[i];
        tree.nodes.emplace_back(node_begin, node_begin + HASH_SIZE);
    }

    tree.depth = decoded->tree_depth;
    tree.has_depth = true;
    tree.security_flags = security_flags_from_tree(decoded);

    secure_merkle_tree_free(decoded);

    return true;
}

bool decode_attestation_bundle(const std::vector<uint8_t>& attestation_cbor,
                               AttestationBundle& attestation,
                               std::string& error) {
    QCBORDecodeContext decode_ctx;
    UsefulBufC encoded{attestation_cbor.data(), attestation_cbor.size()};
    QCBORDecode_Init(&decode_ctx, encoded, QCBOR_DECODE_MODE_NORMAL);

    QCBORItem map_item{};
    QCBORDecode_EnterMap(&decode_ctx, &map_item);
    if (QCBORDecode_GetError(&decode_ctx) != QCBOR_SUCCESS) {
        error = qcbor_err_to_str(QCBORDecode_GetError(&decode_ctx));
        return false;
    }
    if (map_item.uDataType != QCBOR_TYPE_MAP) {
        error = "attestation payload must be a CBOR map";
        return false;
    }

    UsefulBufC pk_root_buf{};
    UsefulBufC merkle_root_buf{};
    UsefulBufC xmss_sig_buf{};
    QCBORDecode_GetByteStringInMapN(&decode_ctx, 1, &pk_root_buf);
    QCBORDecode_GetByteStringInMapN(&decode_ctx, 2, &merkle_root_buf);
    QCBORDecode_GetByteStringInMapN(&decode_ctx, 3, &xmss_sig_buf);
    QCBORDecode_ExitMap(&decode_ctx);
    QCBORError finish_error = QCBORDecode_Finish(&decode_ctx);
    if (finish_error != QCBOR_SUCCESS) {
        error = qcbor_err_to_str(finish_error);
        return false;
    }

    attestation.pk_root = useful_buf_to_vector(pk_root_buf);
    attestation.merkle_root = useful_buf_to_vector(merkle_root_buf);
    attestation.xmss_sig = useful_buf_to_vector(xmss_sig_buf);

    if (!decode_optional_bytes_array_from_map(attestation_cbor, 4, attestation.leaf_hashes, false, error)) {
        return false;
    }
    if (!decode_optional_bytes_array_from_map(attestation_cbor, 5, attestation.host_keys, false, error)) {
        return false;
    }
    if (!decode_optional_bytes_array_from_map(attestation_cbor, 6, attestation.validation_data, false, error)) {
        return false;
    }

    return true;
}

bool decode_source_data_from_payload(const std::vector<uint8_t>& payload_cbor,
                                     std::vector<std::vector<uint8_t>>& source_data,
                                     std::string& error) {
    QCBORDecodeContext decode_ctx;
    UsefulBufC encoded{payload_cbor.data(), payload_cbor.size()};
    QCBORDecode_Init(&decode_ctx, encoded, QCBOR_DECODE_MODE_NORMAL);

    QCBORItem outer_array{};
    QCBORDecode_EnterArray(&decode_ctx, &outer_array);
    if (QCBORDecode_GetError(&decode_ctx) != QCBOR_SUCCESS) {
        error = qcbor_err_to_str(QCBORDecode_GetError(&decode_ctx));
        return false;
    }
    if (outer_array.uDataType != QCBOR_TYPE_ARRAY || outer_array.val.uCount < 2 ||
        outer_array.val.uCount == UINT16_MAX) {
        error = "sign request payload must be [source_data, include_leaf_hashes, ...]";
        return false;
    }

    QCBORItem source_array_item{};
    UsefulBufC encoded_source_array{};
    QCBORDecode_GetArray(&decode_ctx, &source_array_item, &encoded_source_array);
    if (QCBORDecode_GetError(&decode_ctx) != QCBOR_SUCCESS) {
        error = qcbor_err_to_str(QCBORDecode_GetError(&decode_ctx));
        return false;
    }

    bool include_leaf_hashes = false;
    QCBORDecode_GetBool(&decode_ctx, &include_leaf_hashes);
    if (QCBORDecode_GetError(&decode_ctx) != QCBOR_SUCCESS) {
        error = qcbor_err_to_str(QCBORDecode_GetError(&decode_ctx));
        return false;
    }

    QCBORDecode_ExitArray(&decode_ctx);
    const QCBORError finish_error = QCBORDecode_Finish(&decode_ctx);
    if (finish_error != QCBOR_SUCCESS) {
        error = qcbor_err_to_str(finish_error);
        return false;
    }

    (void)include_leaf_hashes;
    return decode_bytes_array(encoded_source_array, source_data, error);
}

bool verify_xmss_signature_verbose(const AttestationBundle& attestation,
                                   const std::vector<uint8_t>& merkle_root,
                                   std::ostream& out,
                                   std::string& failure_reason) {
    out << "\n--- Verifying XMSS Signature ---\n";

    if (attestation.xmss_sig.empty()) {
        out << "FAIL: No XMSS signature found\n";
        failure_reason = "XMSS signature missing";
        return false;
    }
    out << "XMSS Signature present, length: " << attestation.xmss_sig.size() << " bytes\n";

    if (attestation.merkle_root != merkle_root) {
        out << "FAIL: Stardome attestation merkle_root does not match tree root\n";
        failure_reason = "tree root mismatch";
        return false;
    }

    if (attestation.pk_root.empty()) {
        out << "FAIL: No XMSS public key (pk_root) found in attestation\n";
        failure_reason = "XMSS public key missing";
        return false;
    }

    out << "XMSS pk_root present, length: " << attestation.pk_root.size()
        << " bytes, prefix: " << hex_prefix(attestation.pk_root, 8u) << "\n";

    char err[256] = {0};
    const bool xmss_ok = stardome_xmss_verify_detached(attestation.pk_root.data(),
                                                       attestation.pk_root.size(),
                                                       attestation.merkle_root.data(),
                                                       attestation.merkle_root.size(),
                                                       attestation.xmss_sig.data(),
                                                       attestation.xmss_sig.size(),
                                                       err,
                                                       sizeof(err));
    if (xmss_ok) {
        out << "PASS: XMSS signature verifies (pk_root over merkle_root).\n";
        return true;
    }

    out << "FAIL: XMSS signature did not verify";
    if (err[0] != '\0') {
        out << " (" << err << ")";
        failure_reason = err;
    } else {
        failure_reason = "XMSS signature verification failed";
    }
    out << "\n";
    return false;
}

std::string format_validation_data(const std::vector<uint8_t>& raw,
                                   const std::string& scheme_version,
                                   size_t abs_index) {
    std::ostringstream oss;
    const ValidationDescriptor descriptor = describe_validation_data(scheme_version, abs_index);

    oss << "abs=" << abs_index
        << " label=" << descriptor.label
        << " len=" << raw.size();

    switch (descriptor.format) {
        case ValidationFormat::Ascii:
            if (is_printable_ascii(raw)) {
                oss << " text=\"" << ascii_bytes(raw) << "\"";
            }
            break;
        case ValidationFormat::U64Be:
            if (raw.size() == 8u) {
                oss << " u64_be=" << read_be64(raw);
            }
            break;
        case ValidationFormat::U32AndI32Be:
            if (raw.size() == 4u) {
                const uint32_t u32 = read_be32(raw);
                const int32_t i32 = static_cast<int32_t>(u32);
                oss << " u32_be=" << u32 << " i32_be=" << i32;
            }
            break;
        case ValidationFormat::EpochRecord:
            if (raw.size() == 16u) {
                const std::vector<uint8_t> ts(raw.begin(), raw.begin() + 8);
                const std::vector<uint8_t> counter(raw.begin() + 8, raw.begin() + 12);
                const std::vector<uint8_t> drift(raw.begin() + 12, raw.end());
                const uint64_t clock_ts = read_be64(ts);
                const uint32_t clock_counter = read_be32(counter);
                const int32_t clock_drift = static_cast<int32_t>(read_be32(drift));
                oss << " epoch_clock_timestamp=" << clock_ts
                    << " epoch_clock_counter=" << clock_counter
                    << " epoch_clock_drift=" << clock_drift;
            }
            break;
        case ValidationFormat::HexOnly:
            break;
    }

    oss << " hex=" << hex_bytes(raw);

    if (descriptor.format == ValidationFormat::HexOnly) {
        if (raw.size() == 8u) {
            oss << " u64_be=" << read_be64(raw);
        } else if (raw.size() == 4u) {
            const uint32_t u32 = read_be32(raw);
            const int32_t i32 = static_cast<int32_t>(u32);
            oss << " u32_be=" << u32 << " i32_be=" << i32;
        }
    }
    return oss.str();
}

} // namespace

std::string normalize_scheme_version_label(const std::string& scheme) {
    if (!scheme.empty() && (scheme[0] == 'v' || scheme[0] == 'V')) {
        return scheme.substr(1);
    }
    return scheme;
}

bool verify_attestation_bundle_verbose(const std::vector<uint8_t>& tree_cbor,
                                       const std::vector<uint8_t>& attestation_cbor,
                                       const AttestationVerificationOptions& options,
                                       std::ostream& out,
                                       std::string& failure_reason) {
    failure_reason.clear();

    TreeBundle tree;
    AttestationBundle attestation;
    std::string error;
    if (!decode_tree_bundle(tree_cbor, tree, error)) {
        out << "FAIL: Failed to decode tree CBOR: " << error << "\n";
        failure_reason = error;
        return false;
    }
    if (!decode_attestation_bundle(attestation_cbor, attestation, error)) {
        out << "FAIL: Failed to decode attestation CBOR: " << error << "\n";
        failure_reason = error;
        return false;
    }

    std::vector<std::vector<uint8_t>> source_data;
    bool have_source_data = false;
    if (options.payload_cbor != nullptr) {
        if (decode_source_data_from_payload(*options.payload_cbor, source_data, error)) {
            have_source_data = true;
        } else {
            out << "WARN: Failed to decode payload CBOR source_data: " << error << "\n";
        }
    }

    const std::string scheme_version = normalize_scheme_version_label(options.scheme_version);
    out << "\n=== Verifying Response ===\n";
    out << "Scheme version: " << scheme_version << "\n";

    if (tree.nodes.empty()) {
        out << "FAIL: Empty tree nodes\n";
        failure_reason = "empty tree nodes";
        return false;
    }

    const std::vector<uint8_t>& calculated_root = tree.nodes.back();
    const bool root_match = (calculated_root == attestation.merkle_root);

    out << "1. Verifying Tree Binding...\n";
    out << "  Tree Root (from nodes[-1]): " << hex_bytes(calculated_root) << "\n";
    out << "  Stardome attestation Merkle Root:      " << hex_bytes(attestation.merkle_root) << "\n";
    out << (root_match ? "PASS: Tree root matches Stardome attestation root.\n"
                       : "FAIL: Tree root mismatch!\n");

    out << "\n2. Inspecting Stardome Attestation extensions...\n";
    out << "  Leaf Hashes present: " << attestation.leaf_hashes.size() << "\n";
    out << "  Host Keys present:   " << attestation.host_keys.size() << "\n";
    out << "  Validation Data present: " << attestation.validation_data.size() << "\n";

    if (!attestation.validation_data.empty()) {
        out << "\n  Validation Data values:\n";
        for (size_t i = 0; i < attestation.validation_data.size(); ++i) {
            out << "    [" << i << "] "
                << format_validation_data(attestation.validation_data[i], scheme_version, i)
                << "\n";
        }
    }

    if (tree.has_depth && (scheme_version == "1.0.0_0" || scheme_version == "1.0.0_1")) {
        const uint64_t leaf_timestamp_pos = 1u;
        const uint64_t leaf_timestamp_abs = ((1ull << tree.depth) - 1ull) + leaf_timestamp_pos;
        out << "\n2b. Leaf timestamp visibility (type=2, RTC-backed)...\n";
        out << "  Slot: abs=" << leaf_timestamp_abs << " (leaf_pos=" << leaf_timestamp_pos << ")\n";
        if (leaf_timestamp_pos < attestation.leaf_hashes.size()) {
            const std::vector<uint8_t>& ts_leaf_hash = attestation.leaf_hashes[static_cast<size_t>(leaf_timestamp_pos)];
            out << "  leaf_hashes[" << leaf_timestamp_pos << "]=" << hex_bytes(ts_leaf_hash) << "\n";
            if (tree.security_flags.present && leaf_timestamp_pos < tree.nodes.size()) {
                const std::vector<uint8_t> expected_node = hash_leaf(ts_leaf_hash, tree.depth, tree.security_flags);
                if (expected_node == tree.nodes[static_cast<size_t>(leaf_timestamp_pos)]) {
                    out << "  L2 tree node binding: PASS\n";
                } else {
                    out << "  L2 tree node binding: FAIL\n";
                }
            } else {
                out << "  L2 tree node binding: SKIP (no security_flags/tree_nodes)\n";
            }
        } else {
            out << "  leaf_timestamp hash unavailable (leaf_hashes missing or include_leaf_hashes=false)\n";
        }
        if (attestation.validation_data.size() > leaf_timestamp_pos) {
            const std::vector<uint8_t>& raw_timestamp = attestation.validation_data[static_cast<size_t>(leaf_timestamp_pos)];
            out << "  validation_data[" << leaf_timestamp_pos << "]=";
            if (is_printable_ascii(raw_timestamp)) {
                out << "\"" << ascii_bytes(raw_timestamp) << "\"";
            } else {
                out << hex_bytes(raw_timestamp);
            }
            out << "\n";
        } else {
            out << "  validation_data[" << leaf_timestamp_pos << "] unavailable\n";
        }
    }

    bool source_chain_ok = true;
    if (have_source_data && tree.has_depth) {
        const uint64_t num_leaves = (1ull << tree.depth);
        const uint64_t leaf_first = num_leaves - 1ull;
        const uint64_t leaf_source_start = 5u;
        const uint64_t leaf_source_end = (num_leaves == 32u)
            ? 21u
            : std::min<uint64_t>(leaf_source_start + source_data.size() - 1u, num_leaves - 1u);

        out << "\n3. Cross-checking source_data hashes against leaf_hashes and tree_nodes...\n";
        for (size_t i = 0; i < source_data.size(); ++i) {
            const uint64_t leaf_pos = leaf_source_start + i;
            if (leaf_pos > leaf_source_end) {
                out << "  WARN: source_data has more entries (" << source_data.size()
                    << ") than leaf_source slots (" << (leaf_source_end - leaf_source_start + 1u) << ")\n";
                break;
            }

            const uint64_t abs_idx = leaf_first + leaf_pos;
            const std::vector<uint8_t> expected_raw = sha256_bytes(source_data[i]);
            const bool have_leaf_hash = leaf_pos < attestation.leaf_hashes.size();
            const bool l1_ok = have_leaf_hash && expected_raw == attestation.leaf_hashes[static_cast<size_t>(leaf_pos)];
            out << "  [" << i << "] abs=" << abs_idx << " (leaf_pos=" << leaf_pos << ")\n";
            out << "    L1 source_data hash:  " << (l1_ok ? "PASS" : "FAIL") << "\n";
            if (!l1_ok) {
                out << "       expected: " << hex_bytes(expected_raw) << "\n";
                if (have_leaf_hash) {
                    out << "       got:      " << hex_bytes(attestation.leaf_hashes[static_cast<size_t>(leaf_pos)]) << "\n";
                } else {
                    out << "       got:      <leaf_hashes[" << leaf_pos << "] out of range>\n";
                }
                source_chain_ok = false;
            }

            if (l1_ok && tree.security_flags.present) {
                const std::vector<uint8_t> tree_node_hash = hash_leaf(attestation.leaf_hashes[static_cast<size_t>(leaf_pos)], tree.depth, tree.security_flags);
                const bool have_tree_node = leaf_pos < tree.nodes.size();
                const bool l2_ok = have_tree_node && tree_node_hash == tree.nodes[static_cast<size_t>(leaf_pos)];
                out << "    L2 tree node binding: " << (l2_ok ? "PASS" : "FAIL") << "\n";
                if (!l2_ok) {
                    out << "       expected: " << hex_bytes(tree_node_hash) << "\n";
                    if (have_tree_node) {
                        out << "       got:      " << hex_bytes(tree.nodes[static_cast<size_t>(leaf_pos)]) << "\n";
                    } else {
                        out << "       got:      <tree_nodes[" << leaf_pos << "] out of range>\n";
                    }
                    source_chain_ok = false;
                }
            } else if (!l1_ok) {
                out << "    L2 tree node binding: SKIP (L1 failed)\n";
            } else {
                out << "    L2 tree node binding: SKIP (no security_flags in tree)\n";
            }
        }

        if (source_data.size() < (leaf_source_end - leaf_source_start + 1u)) {
            const uint64_t empty_first = leaf_first + leaf_source_start + source_data.size();
            const uint64_t empty_last = leaf_first + leaf_source_end;
            out << "  leaf_source slots abs=" << empty_first << ".." << empty_last
                << ": empty (zero) — no source_data mapped\n";
        }

        out << (source_chain_ok
            ? "  L3 chain: source_data -> leaf_hashes -> tree_nodes -> root -> XMSS: PASS (verified by steps 1 & 4)\n"
            : "  L3 chain: INCOMPLETE (L1/L2 failures above)\n");
    } else {
        out << "\n3. Cross-checking source_data hashes...\n";
        out << "  INFO: No source_data available; skipping leaf_source cross-check\n";
        out << "        (use the attestation request payload context to enable this verification)\n";
    }

    const bool xmss_ok = verify_xmss_signature_verbose(attestation, calculated_root, out, failure_reason);
    const bool overall_ok = root_match && source_chain_ok && xmss_ok;
    out << "\nOverall verification: " << (overall_ok ? "PASS" : "FAIL") << "\n";
    if (!overall_ok && failure_reason.empty()) {
        if (!root_match) {
            failure_reason = "tree root mismatch";
        } else if (!source_chain_ok) {
            failure_reason = "source_data cross-check failed";
        } else {
            failure_reason = "verification failed";
        }
    }

    return overall_ok;
}

} // namespace stardome