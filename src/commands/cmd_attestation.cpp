#include "commands/command_common.hpp"
#include "stardome_flags.h"
#include "swp_bridge.h"
#include "verify/stardome_attestation_verify.hpp"

#include "qcbor/UsefulBuf.h"
#include "qcbor/qcbor_common.h"
#include "qcbor/qcbor_encode.h"

#include <cstdint>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

namespace stardome {

namespace {

enum class AttestationRequestMode {
    Cbor,
    File,
};

constexpr uint32_t kResponseAckSettleMs = 1200u;

struct AttestationResponseCollector {
    std::vector<uint8_t>* tree_sequence;
    swp_rx_meta_t* tree_meta;
    std::vector<uint8_t>* attestation_sequence;
    swp_rx_meta_t* attestation_meta;
    std::string* error;
    bool tree_complete;
    bool attestation_complete;
};

const char* command_name_for_mode(AttestationRequestMode mode) {
    return mode == AttestationRequestMode::File ? "attestation-file" : "attestation";
}

void print_attestation_usage(AttestationRequestMode mode) {
    const bool file_mode = (mode == AttestationRequestMode::File);
    std::cout
        << "Usage: stardome-client [global-options] " << command_name_for_mode(mode) << " [options]\n\n"
        << "Options:\n"
        << (file_mode
                ? "  --payload-file <file>      Send raw source bytes via FLAG_SIGN_FILE\n"
                : "  --payload-cbor <file>      Use prebuilt attestation request payload\n")
        << (file_mode
                ? "  --out-payload-cbor <file>  Write equivalent one-source CBOR payload and exit\n"
                : "  --payload-file <file>      Build a one-source CBOR request from raw file bytes\n")
        << "  --generate-payload <file>  Alias for --out-payload-cbor\n"
        << "  --out-tree <file>          Tree output path (default stardome_tree.bin)\n"
        << "  --out-attestation <file>   Attestation output path (default stardome_attestation.bin)\n"
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

bool receive_attestation_responses(uint32_t timeout_ms,
                                   std::vector<uint8_t>& tree_sequence,
                                   swp_rx_meta_t& tree_meta,
                                   std::vector<uint8_t>& attestation_sequence,
                                   swp_rx_meta_t& attestation_meta,
                                   std::string& error) {
    tree_sequence.clear();
    attestation_sequence.clear();
    tree_meta = swp_rx_meta_t{};
    attestation_meta = swp_rx_meta_t{};

    AttestationResponseCollector collector{
        &tree_sequence,
        &tree_meta,
        &attestation_sequence,
        &attestation_meta,
        &error,
        false,
        false,
    };

    const auto visitor = [](const uint8_t* frame_data,
                            uint16_t frame_len,
                            const swp_rx_meta_t* frame_meta,
                            bool* stream_complete,
                            void* user_ctx) -> bool {
        auto* state = static_cast<AttestationResponseCollector*>(user_ctx);
        const FrameClass tree_class = classify_stardome_response_flag(frame_meta->flags, FLAG_STARDOME_TREE);
        const FrameClass attestation_class = classify_stardome_response_flag(frame_meta->flags, FLAG_STARDOME_ATTESTATION);
        const std::vector<uint8_t> frame_payload(frame_data, frame_data + frame_len);

        if (tree_class == FrameClass::Error || attestation_class == FrameClass::Error) {
            *state->error = "device error frame flags=" + format_flag_hex(frame_meta->flags) +
                            " payload=" + bytes_to_hex(frame_payload);
            return false;
        }

        if (tree_class == FrameClass::Expected) {
            if (state->attestation_complete) {
                *state->error = "received tree frame after attestation completed";
                return false;
            }

            state->tree_sequence->insert(state->tree_sequence->end(), frame_data, frame_data + frame_len);
            *state->tree_meta = *frame_meta;
            if ((frame_meta->flags & FLAG_LAST_FRAME) != 0u) {
                state->tree_complete = true;
            }
            return true;
        }

        if (attestation_class == FrameClass::Expected) {
            if (!state->tree_complete) {
                *state->error = "received attestation frame before tree response completed";
                return false;
            }

            state->attestation_sequence->insert(state->attestation_sequence->end(), frame_data, frame_data + frame_len);
            *state->attestation_meta = *frame_meta;
            if ((frame_meta->flags & FLAG_LAST_FRAME) != 0u) {
                state->attestation_complete = true;
                *stream_complete = true;
            }
            return true;
        }

        *state->error = "unexpected response frame flags=" + format_flag_hex(frame_meta->flags) +
                        " payload=" + bytes_to_hex(frame_payload);
        return false;
    };

    if (!swp_transport_receive_stream_ex(visitor,
                                         &collector,
                                         timeout_ms,
                                         kResponseAckSettleMs)) {
        if (error.empty()) {
            error = "timeout waiting for tree/attestation response stream";
        }
        return false;
    }

    if (!collector.tree_complete || !collector.attestation_complete) {
        error = "incomplete tree/attestation response stream";
        return false;
    }

    return true;
}

std::vector<uint8_t> build_default_sign_payload() {
    const std::vector<uint8_t> source_a = {
        static_cast<uint8_t>('e'), static_cast<uint8_t>('x'), static_cast<uint8_t>('a'),
        static_cast<uint8_t>('m'), static_cast<uint8_t>('p'), static_cast<uint8_t>('l'),
        static_cast<uint8_t>('e'), static_cast<uint8_t>('-'), static_cast<uint8_t>('s'),
        static_cast<uint8_t>('o'), static_cast<uint8_t>('u'), static_cast<uint8_t>('r'),
        static_cast<uint8_t>('c'), static_cast<uint8_t>('e'), static_cast<uint8_t>('-'),
        static_cast<uint8_t>('0')
    };
    const std::vector<uint8_t> source_b = {
        static_cast<uint8_t>('e'), static_cast<uint8_t>('x'), static_cast<uint8_t>('a'),
        static_cast<uint8_t>('m'), static_cast<uint8_t>('p'), static_cast<uint8_t>('l'),
        static_cast<uint8_t>('e'), static_cast<uint8_t>('-'), static_cast<uint8_t>('s'),
        static_cast<uint8_t>('o'), static_cast<uint8_t>('u'), static_cast<uint8_t>('r'),
        static_cast<uint8_t>('c'), static_cast<uint8_t>('e'), static_cast<uint8_t>('-'),
        static_cast<uint8_t>('1')
    };

    size_t encoded_capacity = 96;
    for (int attempt = 0; attempt < 4; ++attempt) {
        std::vector<uint8_t> payload(encoded_capacity, 0);

        UsefulBuf storage{payload.data(), payload.size()};
        QCBOREncodeContext encode_ctx;
        QCBOREncode_Init(&encode_ctx, storage);

        QCBOREncode_OpenArray(&encode_ctx);
        QCBOREncode_OpenArray(&encode_ctx);

        const UsefulBufC source_a_buf{source_a.data(), source_a.size()};
        const UsefulBufC source_b_buf{source_b.data(), source_b.size()};
        QCBOREncode_AddBytes(&encode_ctx, source_a_buf);
        QCBOREncode_AddBytes(&encode_ctx, source_b_buf);

        QCBOREncode_CloseArray(&encode_ctx);
        QCBOREncode_AddBool(&encode_ctx, true);
        QCBOREncode_CloseArray(&encode_ctx);

        UsefulBufC encoded{};
        const QCBORError encode_error = QCBOREncode_Finish(&encode_ctx, &encoded);
        if (encode_error == QCBOR_SUCCESS) {
            payload.resize(encoded.len);
            return payload;
        }
        if (encode_error != QCBOR_ERR_BUFFER_TOO_SMALL) {
            return {};
        }

        encoded_capacity *= 2;
    }

    return {};
}

std::vector<uint8_t> build_sign_payload_from_file(const std::vector<uint8_t>& source_data) {
    size_t encoded_capacity = source_data.size() + 32;
    for (int attempt = 0; attempt < 4; ++attempt) {
        std::vector<uint8_t> payload(encoded_capacity, 0);

        UsefulBuf storage{payload.data(), payload.size()};
        QCBOREncodeContext encode_ctx;
        QCBOREncode_Init(&encode_ctx, storage);

        QCBOREncode_OpenArray(&encode_ctx);
        QCBOREncode_OpenArray(&encode_ctx);
        const UsefulBufC source_buf{source_data.data(), source_data.size()};
        QCBOREncode_AddBytes(&encode_ctx, source_buf);
        QCBOREncode_CloseArray(&encode_ctx);
        QCBOREncode_AddBool(&encode_ctx, true);
        QCBOREncode_CloseArray(&encode_ctx);

        UsefulBufC encoded{};
        const QCBORError encode_error = QCBOREncode_Finish(&encode_ctx, &encoded);
        if (encode_error == QCBOR_SUCCESS) {
            payload.resize(encoded.len);
            return payload;
        }
        if (encode_error != QCBOR_ERR_BUFFER_TOO_SMALL) {
            return {};
        }

        encoded_capacity *= 2;
    }

    return {};
}

} // namespace

int run_attestation_command_impl(const AppConfig& cfg,
                                 int argc,
                                 char** argv,
                                 AttestationRequestMode mode) {
    std::string payload_cbor_file;
    std::string payload_file;
    std::string out_payload_cbor_file;
    std::string out_tree_file = "stardome_tree.bin";
    std::string out_attestation_file = "stardome_attestation.bin";
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
            print_attestation_usage(mode);
            return 0;
        }
        if (arg == "--payload-cbor") {
            const char* value = need_value("--payload-cbor", i);
            if (!value) {
                return 2;
            }
            payload_cbor_file = value;
        } else if (arg == "--payload-file") {
            const char* value = need_value("--payload-file", i);
            if (!value) {
                return 2;
            }
            payload_file = value;
        } else if (arg == "--out-payload-cbor") {
            const char* value = need_value("--out-payload-cbor", i);
            if (!value) {
                return 2;
            }
            out_payload_cbor_file = value;
        } else if (arg == "--generate-payload") {
            const char* value = need_value("--generate-payload", i);
            if (!value) {
                return 2;
            }
            out_payload_cbor_file = value;
        } else if (arg == "--out-tree") {
            const char* value = need_value("--out-tree", i);
            if (!value) {
                return 2;
            }
            out_tree_file = value;
        } else if (arg == "--out-attestation") {
            const char* value = need_value("--out-attestation", i);
            if (!value) {
                return 2;
            }
            out_attestation_file = value;
        } else if (arg == "--timeout-ms") {
            const char* value = need_value("--timeout-ms", i);
            if (!value) {
                return 2;
            }
            timeout_ms = static_cast<uint32_t>(std::strtoul(value, nullptr, 10));
        } else {
            std::cerr << "Unknown " << command_name_for_mode(mode) << " option: " << arg << "\n";
            print_attestation_usage(mode);
            return 2;
        }
    }

    const bool file_mode = (mode == AttestationRequestMode::File);

    if (!payload_cbor_file.empty() && !out_payload_cbor_file.empty()) {
        std::cerr << "--payload-cbor cannot be combined with --out-payload-cbor\n";
        return 2;
    }
    if (!payload_cbor_file.empty() && !payload_file.empty()) {
        std::cerr << "--payload-cbor cannot be combined with --payload-file\n";
        return 2;
    }
    if (file_mode && !payload_cbor_file.empty()) {
        std::cerr << "attestation-file does not accept --payload-cbor; use --payload-file\n";
        return 2;
    }
    if (file_mode && payload_file.empty()) {
        std::cerr << "attestation-file requires --payload-file\n";
        return 2;
    }

    std::vector<uint8_t> wire_payload;
    std::vector<uint8_t> verify_payload;
    uint8_t request_flag = file_mode ? FLAG_SIGN_FILE : FLAG_SIGN;
    uint8_t request_encoding = file_mode ? ENCODING_BINARY : ENCODING_CBOR;

    if (!payload_cbor_file.empty()) {
        wire_payload = read_binary_file(payload_cbor_file);
        if (wire_payload.empty()) {
            std::cerr << "Failed to read payload CBOR file: " << payload_cbor_file << "\n";
            return 2;
        }
        verify_payload = wire_payload;
    } else if (!payload_file.empty()) {
        const std::vector<uint8_t> source_data = read_binary_file(payload_file);
        if (source_data.empty()) {
            std::cerr << "Failed to read payload source file: " << payload_file << "\n";
            return 2;
        }

        verify_payload = build_sign_payload_from_file(source_data);
        if (verify_payload.empty()) {
            std::cerr << "Failed to build attestation payload\n";
            return 2;
        }

        if (file_mode) {
            if (!out_payload_cbor_file.empty()) {
                wire_payload = verify_payload;
            } else {
                wire_payload = source_data;
            }
        } else {
            wire_payload = verify_payload;
        }
    } else {
        wire_payload = build_default_sign_payload();
        verify_payload = wire_payload;
    }

    if (wire_payload.empty()) {
        std::cerr << "Failed to build attestation payload\n";
        return 2;
    }

    if (verify_payload.empty()) {
        verify_payload = wire_payload;
    }

    if (!out_payload_cbor_file.empty()) {
        if (!write_binary_file(out_payload_cbor_file, verify_payload)) {
            std::cerr << "Failed to write payload output file: " << out_payload_cbor_file << "\n";
            return 2;
        }
        std::cout << "Wrote attestation request payload to " << out_payload_cbor_file
                  << " (" << verify_payload.size() << " bytes)\n";
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

    const bool sent = swp_transport_send(wire_payload.data(),
                                         static_cast<uint32_t>(wire_payload.size()),
                                         static_cast<uint8_t>(request_flag | FLAG_LAST_FRAME),
                                         request_encoding);
    if (!sent) {
        std::cerr << "Failed to send attestation request\n";
        swp_transport_close();
        return 2;
    }

    std::vector<uint8_t> tree_response;
    std::vector<uint8_t> attestation_response;
    swp_rx_meta_t response_1_meta{};
    swp_rx_meta_t response_2_meta{};
    std::string receive_error;
    const bool got_responses = receive_attestation_responses(timeout_ms,
                                                             tree_response,
                                                             response_1_meta,
                                                             attestation_response,
                                                             response_2_meta,
                                                             receive_error);
    if (!got_responses || tree_response.empty()) {
        std::cerr << "Failed to receive tree response: " << receive_error << "\n";
        swp_transport_close();
        return 1;
    }

    const FrameClass tree_class = classify_stardome_response_flag(response_1_meta.flags, FLAG_STARDOME_TREE);
    if (tree_class == FrameClass::Error) {
        std::cerr << "Device reported sign/tree error (flags=" << format_flag_hex(response_1_meta.flags)
                  << "): " << bytes_to_hex(tree_response) << "\n";
        swp_transport_close();
        return 1;
    }
    if (tree_class == FrameClass::Unexpected) {
        std::cerr << "Unexpected attestation tree response frame (flags=" << format_flag_hex(response_1_meta.flags)
                  << ", payload=" << tree_response.size() << " bytes)\n";
        swp_transport_close();
        return 1;
    }

    if (!write_binary_file(out_tree_file, tree_response)) {
        std::cerr << "Failed to write tree output file: " << out_tree_file << "\n";
        swp_transport_close();
        return 2;
    }

    if (attestation_response.empty()) {
        std::cerr << "Failed to receive attestation response: " << receive_error << "\n";
        swp_transport_close();
        return 1;
    }

    const FrameClass attestation_class = classify_stardome_response_flag(response_2_meta.flags, FLAG_STARDOME_ATTESTATION);
    if (attestation_class == FrameClass::Error) {
        std::cerr << "Device reported attestation error (flags=" << format_flag_hex(response_2_meta.flags)
                  << "): " << bytes_to_hex(attestation_response) << "\n";
        swp_transport_close();
        return 1;
    }
    if (attestation_class == FrameClass::Unexpected) {
        std::cerr << "Unexpected attestation response frame (flags=" << format_flag_hex(response_2_meta.flags)
                  << ", payload=" << attestation_response.size() << " bytes)\n";
        swp_transport_close();
        return 1;
    }

    if (!write_binary_file(out_attestation_file, attestation_response)) {
        std::cerr << "Failed to write attestation output file: " << out_attestation_file << "\n";
        swp_transport_close();
        return 2;
    }

    swp_transport_close();

    AttestationVerificationOptions verify_options;
    verify_options.scheme_version = cfg.scheme;
    verify_options.payload_cbor = &verify_payload;

    std::string verify_failure;
    const bool verify_ok = verify_attestation_bundle_verbose(tree_response,
                                                             attestation_response,
                                                             verify_options,
                                                             std::cout,
                                                             verify_failure);

    std::cout << "Wrote tree response to " << out_tree_file << " (" << tree_response.size() << " bytes)\n";
    std::cout << "Wrote attestation response to " << out_attestation_file << " (" << attestation_response.size() << " bytes)\n";
    if (!verify_ok) {
        std::cerr << "Attestation verification failed: " << verify_failure << "\n";
        return 1;
    }

    return 0;
}

int run_attestation_command(const AppConfig& cfg, int argc, char** argv) {
    return run_attestation_command_impl(cfg, argc, argv, AttestationRequestMode::Cbor);
}

int run_attestation_file_command(const AppConfig& cfg, int argc, char** argv) {
    return run_attestation_command_impl(cfg, argc, argv, AttestationRequestMode::File);
}

} // namespace stardome
