#include "commands/command_common.hpp"
#include "stardome_flags.h"
#include "swp_bridge.h"

#include "qcbor/UsefulBuf.h"
#include "qcbor/qcbor_common.h"
#include "qcbor/qcbor_decode.h"
#include "qcbor/qcbor_encode.h"
#include "qcbor/qcbor_spiffy_decode.h"

#include <cstdint>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

namespace stardome {

namespace {

constexpr size_t kMaxProofResponseBytes = 65535u;

void print_proof_usage() {
    std::cout
        << "Usage: stardome-client [global-options] proof [options]\n\n"
        << "Options:\n"
        << "  --payload-cbor <file>      Use prebuilt proof request payload\n"
        << "  --out-payload-cbor <file>  Generate proof request payload to file and exit\n"
        << "  --tree-file <file>         Tree input path (default stardome_tree.bin)\n"
        << "  --leaf-index <n>           Leaf index (required unless --payload-cbor is used)\n"
        << "  --out-proof <file>         Proof output path (default stardome_proof.bin)\n"
        << "  --timeout-ms <ms>          Response timeout in milliseconds (default 20000)\n"
        << "  -h, --help                 Show this help\n";
}

std::vector<uint8_t> read_binary_file(const std::string& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in.is_open()) {
        return {};
    }
    return std::vector<uint8_t>(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
}

bool write_binary_file(const std::string& path, const std::vector<uint8_t>& data) {
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    if (!out.is_open()) {
        return false;
    }
    out.write(reinterpret_cast<const char*>(data.data()), static_cast<std::streamsize>(data.size()));
    return static_cast<bool>(out);
}

bool encode_proof_payload(const std::vector<uint8_t>& tree_payload,
                          uint64_t leaf_index,
                          std::vector<uint8_t>& out,
                          std::string& error) {
    size_t encoded_capacity = tree_payload.size() + 32;
    for (int attempt = 0; attempt < 4; ++attempt) {
        out.assign(encoded_capacity, 0);

        UsefulBuf storage{out.data(), out.size()};
        QCBOREncodeContext encode_ctx;
        QCBOREncode_Init(&encode_ctx, storage);
        QCBOREncode_OpenArray(&encode_ctx);

        const UsefulBufC tree_item{tree_payload.data(), tree_payload.size()};
        QCBOREncode_AddEncoded(&encode_ctx, tree_item);
        QCBOREncode_AddUInt64(&encode_ctx, leaf_index);
        QCBOREncode_CloseArray(&encode_ctx);

        UsefulBufC encoded{};
        const QCBORError encode_error = QCBOREncode_Finish(&encode_ctx, &encoded);
        if (encode_error == QCBOR_SUCCESS) {
            out.resize(encoded.len);
            return true;
        }
        if (encode_error != QCBOR_ERR_BUFFER_TOO_SMALL) {
            error = qcbor_err_to_str(encode_error);
            return false;
        }

        encoded_capacity *= 2;
    }

    error = "proof payload encoding exceeded retry capacity";
    return false;
}

struct ProofSummary {
    uint64_t version = 0;
    std::vector<uint64_t> indices;
    size_t lemmas_array_len = 0;
    uint64_t lemmas_count = 0;
    bool has_expected_depth = false;
    uint64_t expected_depth = 0;
};

bool decode_uint_array(UsefulBufC encoded_array,
                       std::vector<uint64_t>& out,
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
        error = "indices must be a definite-length CBOR array";
        return false;
    }

    out.clear();
    out.reserve(entered_array.val.uCount);
    for (uint16_t i = 0; i < entered_array.val.uCount; ++i) {
        uint64_t value = 0;
        QCBORDecode_GetUInt64(&array_ctx, &value);
        if (QCBORDecode_GetError(&array_ctx) != QCBOR_SUCCESS) {
            error = "indices array contains non-uint item";
            return false;
        }
        out.push_back(value);
    }

    QCBORDecode_ExitArray(&array_ctx);
    const QCBORError finish_error = QCBORDecode_Finish(&array_ctx);
    if (finish_error != QCBOR_SUCCESS) {
        error = qcbor_err_to_str(finish_error);
        return false;
    }

    return true;
}

bool decode_lemmas_array_len(UsefulBufC encoded_array,
                             size_t& out_len,
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
        error = "lemmas must be a definite-length CBOR array";
        return false;
    }

    out_len = entered_array.val.uCount;
    QCBORItem lemma_item{};
    for (uint16_t i = 0; i < entered_array.val.uCount; ++i) {
        QCBORDecode_VGetNext(&array_ctx, &lemma_item);
        if (QCBORDecode_GetError(&array_ctx) != QCBOR_SUCCESS) {
            error = qcbor_err_to_str(QCBORDecode_GetError(&array_ctx));
            return false;
        }
        if (lemma_item.uDataType != QCBOR_TYPE_BYTE_STRING) {
            error = "lemmas array contains non-byte-string item";
            return false;
        }
    }

    QCBORDecode_ExitArray(&array_ctx);
    const QCBORError finish_error = QCBORDecode_Finish(&array_ctx);
    if (finish_error != QCBOR_SUCCESS) {
        error = qcbor_err_to_str(finish_error);
        return false;
    }

    return true;
}

bool try_decode_expected_depth(const std::vector<uint8_t>& payload,
                               uint64_t& expected_depth,
                               bool& has_expected_depth,
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

    uint64_t value = 0;
    QCBORDecode_GetUInt64InMapN(&decode_ctx, 8, &value);
    QCBORDecode_ExitMap(&decode_ctx);
    const QCBORError finish_error = QCBORDecode_Finish(&decode_ctx);
    if (finish_error == QCBOR_SUCCESS) {
        has_expected_depth = true;
        expected_depth = value;
        return true;
    }

    if (finish_error == QCBOR_ERR_LABEL_NOT_FOUND) {
        has_expected_depth = false;
        expected_depth = 0;
        return true;
    }

    error = qcbor_err_to_str(finish_error);
    return false;
}

bool decode_proof_summary(const std::vector<uint8_t>& payload,
                          ProofSummary& summary,
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
        error = "proof payload must be a CBOR map";
        return false;
    }

    UsefulBufC encoded_indices{};
    UsefulBufC encoded_lemmas{};
    QCBORItem indices_item{};
    QCBORItem lemmas_item{};

    QCBORDecode_GetUInt64InMapN(&decode_ctx, 1, &summary.version);
    QCBORDecode_GetArrayFromMapN(&decode_ctx, 2, &indices_item, &encoded_indices);
    QCBORDecode_GetArrayFromMapN(&decode_ctx, 3, &lemmas_item, &encoded_lemmas);
    QCBORDecode_GetUInt64InMapN(&decode_ctx, 5, &summary.lemmas_count);
    QCBORDecode_ExitMap(&decode_ctx);

    const QCBORError finish_error = QCBORDecode_Finish(&decode_ctx);
    if (finish_error != QCBOR_SUCCESS) {
        error = qcbor_err_to_str(finish_error);
        return false;
    }

    if (!decode_uint_array(encoded_indices, summary.indices, error)) {
        return false;
    }

    if (!decode_lemmas_array_len(encoded_lemmas, summary.lemmas_array_len, error)) {
        return false;
    }

    if (!try_decode_expected_depth(payload, summary.expected_depth, summary.has_expected_depth, error)) {
        return false;
    }

    return true;
}

bool validate_proof_summary(const ProofSummary& summary,
                            std::string& failure_reason) {
    if (summary.indices.empty()) {
        failure_reason = "indices array is empty";
        return false;
    }

    if (summary.lemmas_count != summary.lemmas_array_len) {
        failure_reason = "lemmas_count does not match lemmas array length";
        return false;
    }

    if (summary.version >= 2) {
        if (!summary.has_expected_depth) {
            failure_reason = "expected_depth is missing for proof version >= 2";
            return false;
        }
        if (summary.indices.size() != 1) {
            failure_reason = "proof version >= 2 must contain exactly one index";
            return false;
        }
        if (summary.lemmas_count != summary.expected_depth) {
            failure_reason = "lemmas_count does not match expected_depth";
            return false;
        }
    }

    return true;
}

std::string format_indices(const std::vector<uint64_t>& indices) {
    std::ostringstream oss;
    oss << "[";
    for (size_t i = 0; i < indices.size(); ++i) {
        if (i != 0) {
            oss << ", ";
        }
        oss << indices[i];
    }
    oss << "]";
    return oss.str();
}

} // namespace

int run_proof_command(const AppConfig& cfg, int argc, char** argv) {
    std::string payload_cbor_file;
    std::string out_payload_cbor_file;
    std::string tree_file = "stardome_tree.bin";
    std::string out_proof_file = "stardome_proof.bin";
    uint64_t leaf_index = 0;
    bool leaf_index_set = false;
    uint32_t timeout_ms = 20000;

    auto need_value = [&](const std::string& option, int& index) -> const char* {
        if (index + 1 >= argc) {
            std::cerr << "Missing value for " << option << "\n";
            return nullptr;
        }
        return argv[++index];
    };

    for (int i = 0; i < argc; ++i) {
        const std::string arg = argv[i];
        if (arg == "-h" || arg == "--help") {
            print_proof_usage();
            return 0;
        }
        if (arg == "--payload-cbor") {
            const char* value = need_value("--payload-cbor", i);
            if (!value) {
                return 2;
            }
            payload_cbor_file = value;
        } else if (arg == "--out-payload-cbor") {
            const char* value = need_value("--out-payload-cbor", i);
            if (!value) {
                return 2;
            }
            out_payload_cbor_file = value;
        } else if (arg == "--tree-file") {
            const char* value = need_value("--tree-file", i);
            if (!value) {
                return 2;
            }
            tree_file = value;
        } else if (arg == "--leaf-index") {
            const char* value = need_value("--leaf-index", i);
            if (!value) {
                return 2;
            }
            const auto parsed = std::strtoll(value, nullptr, 10);
            if (parsed < 0) {
                std::cerr << "leaf-index must be >= 0\n";
                return 2;
            }
            leaf_index = static_cast<uint64_t>(parsed);
            leaf_index_set = true;
        } else if (arg == "--out-proof") {
            const char* value = need_value("--out-proof", i);
            if (!value) {
                return 2;
            }
            out_proof_file = value;
        } else if (arg == "--timeout-ms") {
            const char* value = need_value("--timeout-ms", i);
            if (!value) {
                return 2;
            }
            timeout_ms = static_cast<uint32_t>(std::strtoul(value, nullptr, 10));
        } else {
            std::cerr << "Unknown proof option: " << arg << "\n";
            print_proof_usage();
            return 2;
        }
    }

    if (!payload_cbor_file.empty() && !out_payload_cbor_file.empty()) {
        std::cerr << "--payload-cbor cannot be combined with --out-payload-cbor\n";
        return 2;
    }

    if (payload_cbor_file.empty() && !leaf_index_set) {
        std::cerr << "--leaf-index is required unless --payload-cbor is used\n";
        return 2;
    }

    std::vector<uint8_t> payload;
    if (!payload_cbor_file.empty()) {
        payload = read_binary_file(payload_cbor_file);
        if (payload.empty()) {
            std::cerr << "Failed to read payload CBOR file: " << payload_cbor_file << "\n";
            return 2;
        }
    } else {
        const std::vector<uint8_t> tree_payload = read_binary_file(tree_file);
        if (tree_payload.empty()) {
            std::cerr << "Failed to read tree file: " << tree_file << "\n";
            return 2;
        }

        std::string encode_error;
        if (!encode_proof_payload(tree_payload, leaf_index, payload, encode_error)) {
            std::cerr << "Failed to encode proof payload: " << encode_error << "\n";
            return 2;
        }
    }

    if (!out_payload_cbor_file.empty()) {
        if (!write_binary_file(out_payload_cbor_file, payload)) {
            std::cerr << "Failed to write payload output file: " << out_payload_cbor_file << "\n";
            return 2;
        }
        std::cout << "Wrote proof request payload to " << out_payload_cbor_file
                  << " (" << payload.size() << " bytes)\n";
        return 0;
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
                                         static_cast<uint8_t>(FLAG_STARDOME_PROOF | FLAG_LAST_FRAME),
                                         ENCODING_CBOR);
    if (!sent) {
        std::cerr << "Failed to send proof request\n";
        swp_transport_close();
        return 2;
    }

    std::vector<uint8_t> response_buf(kMaxProofResponseBytes, 0u);
    uint16_t response_len = 0;
    swp_rx_meta_t response_meta{};
    const bool received = swp_transport_receive_ex(response_buf.data(),
                                                   response_buf.size(),
                                                   &response_len,
                                                   &response_meta,
                                                   timeout_ms);
    swp_transport_close();
    if (!received || response_len == 0) {
        std::cerr << "Timeout waiting for proof response\n";
        return 1;
    }

    const FrameClass frame_class = classify_stardome_response_flag(response_meta.flags, FLAG_STARDOME_PROOF);
    if (frame_class == FrameClass::Error) {
        const std::vector<uint8_t> err(response_buf.begin(), response_buf.begin() + response_len);
        std::cerr << "Device reported proof error (flags=" << format_flag_hex(response_meta.flags)
                  << "): " << bytes_to_hex(err) << "\n";
        return 1;
    }
    if (frame_class == FrameClass::Unexpected) {
        std::cerr << "Unexpected proof response frame (flags=" << format_flag_hex(response_meta.flags)
                  << ", payload=" << response_len << " bytes)\n";
        return 1;
    }

    const std::vector<uint8_t> response(response_buf.begin(), response_buf.begin() + response_len);
    if (!write_binary_file(out_proof_file, response)) {
        std::cerr << "Failed to write proof output file: " << out_proof_file << "\n";
        return 2;
    }

    std::cout << "Wrote proof response to " << out_proof_file << " (" << response_len << " bytes)\n";

    ProofSummary summary;
    std::string decode_error;
    if (!decode_proof_summary(response, summary, decode_error)) {
        std::cout << "Proof decode: FAIL\n";
        std::cout << "Reason: " << decode_error << "\n";
        return 1;
    }

    std::string proof_failure_reason;
    const bool proof_ok = validate_proof_summary(summary, proof_failure_reason);
    std::cout << "Proof decode: " << (proof_ok ? "PASS" : "FAIL") << "\n";
    std::cout << "Decoded proof summary:\n";
    std::cout << "  version:         " << summary.version << "\n";
    std::cout << "  indices:         " << format_indices(summary.indices) << "\n";
    std::cout << "  lemmas_count:    " << summary.lemmas_count
              << " (lemmas array len=" << summary.lemmas_array_len << ")\n";
    if (summary.has_expected_depth) {
        std::cout << "  expected_depth:  " << summary.expected_depth << "\n";
    }

    if (!proof_ok) {
        std::cout << "Reason: " << proof_failure_reason << "\n";
        return 1;
    }

    return 0;
}

} // namespace stardome
