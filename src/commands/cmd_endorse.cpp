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
#include <ctime>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

namespace stardome {

namespace {

constexpr size_t kMaxEndorseTreeBytes = 65535u;
constexpr size_t kMaxEndorseAttBytes = 65535u;
constexpr uint32_t kResponseAckSettleMs = 1200u;

void print_endorse_usage() {
    std::cout
        << "Usage: stardome-client [global-options] endorse [options]\n\n"
        << "Build a sign_request_payload (SEAD v1.1.2 scheme) and send to the\n"
        << "module via FLAG_SIGN. The module builds a Merkle tree, signs the\n"
        << "root, and returns the attestation. The command extracts the\n"
        << "merkle_root and XMSS signature for gen-bootstrap.\n\n"
        << "Raw data mode (--data-hex wraps bytes in [[<data>], true]):\n"
        << "  --data-hex <hex>           Raw hex bytes to place as source_data\n\n"
        << "Org-endorsement builder mode (recommended):\n"
        << "  --org-id <hex>             Organization ID (hex bytes)\n"
        << "  --org-pk <hex>             Organization XMSS public key (hex)\n"
        << "  --not-before <sec>         Validity start (default: current time)\n"
        << "  --not-after <sec>          Validity end (default: 0 = no expiry)\n\n"
        << "Output options:\n"
        << "  --out-tree <file>          Write tree binary to file\n"
        << "  --out-attestation <file>   Write attestation binary to file\n"
        << "  --quiet                    Suppress console hex output\n"
        << "  --timeout-ms <ms>          Response timeout in milliseconds (default 20000)\n"
        << "  -h, --help                 Show this help\n";
}

std::string hex_bytes_str(const std::vector<uint8_t>& data) {
    static const char hex[] = "0123456789abcdef";
    std::string out(2 * data.size(), '\0');
    for (size_t i = 0; i < data.size(); ++i) {
        out[2 * i]     = hex[(data[i] >> 4) & 0xf];
        out[2 * i + 1] = hex[data[i] & 0xf];
    }
    return out;
}

std::vector<uint8_t> hex_to_bytes(const std::string& hex) {
    std::vector<uint8_t> bytes;
    bytes.reserve(hex.size() / 2);
    size_t start = 0;
    if (hex.size() > 2 && hex[0] == '0' && (hex[1] == 'x' || hex[1] == 'X'))
        start = 2;
    for (size_t i = start; i + 1 < hex.size(); i += 2) {
        auto c1 = hex[i], c2 = hex[i + 1];
        auto h2v = [](char c) -> uint8_t {
            if (c >= '0' && c <= '9') return static_cast<uint8_t>(c - '0');
            if (c >= 'a' && c <= 'f') return static_cast<uint8_t>(c - 'a' + 10);
            if (c >= 'A' && c <= 'F') return static_cast<uint8_t>(c - 'A' + 10);
            return 0;
        };
        bytes.push_back(static_cast<uint8_t>((h2v(c1) << 4) | h2v(c2)));
    }
    return bytes;
}

bool is_hex_str(const std::string& s) {
    size_t start = 0;
    if (s.size() > 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X'))
        start = 2;
    if ((s.size() - start) < 2) return false;
    if ((s.size() - start) % 2 != 0) return false;
    for (size_t i = start; i < s.size(); ++i) {
        auto c = s[i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')))
            return false;
    }
    return true;
}

/// Build sign_request_payload = [[bstr(org_id+org_pk), bstr(nb_8be+na_8be)], true]
///
/// NOTE: The CBOR source_data entries are hashed individually and mapped onto
/// leaf_source slots in the attestation tree.  The default scheme
/// (STARDOME_TREE_SCHEME_1_0_0_0, depth=3) has only 3 leaf_source slots, so the
/// 4 SEAD fields cannot be placed as separate entries.  We concatenate
/// (org_id+org_pk) into one bstr and (not_before+not_after) into another.
///
/// The verifier MUST know this concatenation scheme to split source_data back
/// into the original 4 fields when constructing the org_genesis_body for SEAD.
///
/// not_before and not_after are encoded as 8-byte big-endian for deterministic
/// leaf content.
bool build_sign_request_payload(const std::vector<uint8_t>& org_id,
                                const std::vector<uint8_t>& org_pk,
                                uint64_t not_before,
                                uint64_t not_after,
                                std::vector<uint8_t>& out,
                                std::string& error) {
    auto uint64_to_8be = [](uint64_t v) -> std::vector<uint8_t> {
        std::vector<uint8_t> b(8);
        for (int i = 7; i >= 0; --i) {
            b[i] = static_cast<uint8_t>(v & 0xff);
            v >>= 8;
        }
        return b;
    };
    auto nb = uint64_to_8be(not_before);
    auto na = uint64_to_8be(not_after);

    // Pack org_id + org_pk into one bstr, nb + na into another.
    std::vector<uint8_t> org_packed = org_id;
    org_packed.insert(org_packed.end(), org_pk.begin(), org_pk.end());
    std::vector<uint8_t> ts_packed = nb;
    ts_packed.insert(ts_packed.end(), na.begin(), na.end());

    size_t capacity = org_packed.size() + ts_packed.size() + 64;
    for (int attempt = 0; attempt < 4; ++attempt) {
        out.assign(capacity, 0);
        UsefulBuf storage{out.data(), out.size()};
        QCBOREncodeContext ctx;
        QCBOREncode_Init(&ctx, storage);

        QCBOREncode_OpenArray(&ctx);           // outer array
        QCBOREncode_OpenArray(&ctx);            // source_data array
        QCBOREncode_AddBytes(&ctx, UsefulBufC{org_packed.data(), org_packed.size()});
        QCBOREncode_AddBytes(&ctx, UsefulBufC{ts_packed.data(), ts_packed.size()});
        QCBOREncode_CloseArray(&ctx);
        QCBOREncode_AddBool(&ctx, true);        // include leaf_hashes
        QCBOREncode_CloseArray(&ctx);

        UsefulBufC encoded{};
        QCBORError err = QCBOREncode_Finish(&ctx, &encoded);
        if (err == QCBOR_SUCCESS) {
            out.resize(encoded.len);
            return true;
        }
        if (err != QCBOR_ERR_BUFFER_TOO_SMALL) {
            error = qcbor_err_to_str(err);
            return false;
        }
        capacity *= 2;
    }
    error = "payload encoding exceeded retry capacity";
    return false;
}

/// Receive two responses: tree (FLAG_STARDOME_TREE) then attestation (FLAG_STARDOME_ATTESTATION).
bool receive_endorse_responses(uint32_t timeout_ms,
                               std::vector<uint8_t>& tree_out,
                               swp_rx_meta_t& tree_meta,
                               std::vector<uint8_t>& att_out,
                               swp_rx_meta_t& att_meta,
                               std::string& error) {
    tree_out.clear();
    att_out.clear();
    tree_meta = swp_rx_meta_t{};
    att_meta = swp_rx_meta_t{};

    struct EndorsementResponseCollector {
        std::vector<uint8_t>* tree_sequence;
        swp_rx_meta_t* tree_meta;
        std::vector<uint8_t>* attestation_sequence;
        swp_rx_meta_t* att_meta;
        std::string* error;
        bool tree_complete;
        bool attestation_complete;
    } collector{
        &tree_out,
        &tree_meta,
        &att_out,
        &att_meta,
        &error,
        false,
        false,
    };

    const auto visitor = [](const uint8_t* frame_data,
                            uint16_t frame_len,
                            const swp_rx_meta_t* frame_meta,
                            bool* stream_complete,
                            void* user_ctx) -> bool {
        auto* state = static_cast<EndorsementResponseCollector*>(user_ctx);
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
            *state->att_meta = *frame_meta;
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

/// Parse attestation CBOR (v1 scheme: map keys 1=pk, 2=merkle_root, 3=sig).
/// NOTE: When upgrading to attestation schema v2.0.0, keys change:
///       1=installation_id, 2=xmss_pk, 4=merkle_root, 5=xmss_sig.
///       This function must be updated at that point.
bool parse_attestation_fields(const std::vector<uint8_t>& att_cbor,
                              std::vector<uint8_t>& merkle_root,
                              std::vector<uint8_t>& xmss_sig,
                              std::vector<uint8_t>& xmss_pk,
                              std::string& error) {
    QCBORDecodeContext ctx;
    UsefulBufC encoded{att_cbor.data(), att_cbor.size()};
    QCBORDecode_Init(&ctx, encoded, QCBOR_DECODE_MODE_NORMAL);

    QCBORItem map_item{};
    QCBORDecode_EnterMap(&ctx, &map_item);
    if (QCBORDecode_GetError(&ctx) != QCBOR_SUCCESS) {
        error = qcbor_err_to_str(QCBORDecode_GetError(&ctx));
        return false;
    }
    if (map_item.uDataType != QCBOR_TYPE_MAP) {
        error = "attestation must be a CBOR map";
        return false;
    }

    UsefulBufC pk_buf{}, mr_buf{}, sig_buf{};
    QCBORDecode_GetByteStringInMapN(&ctx, 1, &pk_buf);
    QCBORDecode_GetByteStringInMapN(&ctx, 2, &mr_buf);
    QCBORDecode_GetByteStringInMapN(&ctx, 3, &sig_buf);
    QCBORDecode_ExitMap(&ctx);
    QCBORError err = QCBORDecode_Finish(&ctx);
    if (err != QCBOR_SUCCESS) {
        error = qcbor_err_to_str(err);
        return false;
    }

    xmss_pk.assign(static_cast<const uint8_t*>(pk_buf.ptr),
                   static_cast<const uint8_t*>(pk_buf.ptr) + pk_buf.len);
    merkle_root.assign(static_cast<const uint8_t*>(mr_buf.ptr),
                       static_cast<const uint8_t*>(mr_buf.ptr) + mr_buf.len);
    xmss_sig.assign(static_cast<const uint8_t*>(sig_buf.ptr),
                    static_cast<const uint8_t*>(sig_buf.ptr) + sig_buf.len);

    if (merkle_root.empty()) {
        error = "attestation missing merkle_root";
        return false;
    }
    if (xmss_sig.empty()) {
        error = "attestation missing xmss_sig";
        return false;
    }
    return true;
}

} // namespace

int run_endorse_command(const AppConfig& cfg, int argc, char** argv) {
    std::string data_hex;
    std::string org_id_hex, org_pk_hex;
    int64_t not_before_val = 0, not_after_val = 0;
    std::string out_tree, out_attestation;
    uint32_t timeout_ms = 20000;
    bool has_build_args = false;
    bool quiet = false;

    for (int i = 0; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--data-hex" && i + 1 < argc) {
            data_hex = argv[++i];
        } else if (arg == "--org-id" && i + 1 < argc) {
            org_id_hex = argv[++i];
            has_build_args = true;
        } else if (arg == "--org-pk" && i + 1 < argc) {
            org_pk_hex = argv[++i];
            has_build_args = true;
        } else if (arg == "--not-before" && i + 1 < argc) {
            not_before_val = std::stoll(argv[++i]);
            has_build_args = true;
        } else if (arg == "--not-after" && i + 1 < argc) {
            not_after_val = std::stoll(argv[++i]);
            has_build_args = true;
        } else if (arg == "--out-tree" && i + 1 < argc) {
            out_tree = argv[++i];
        } else if (arg == "--out-attestation" && i + 1 < argc) {
            out_attestation = argv[++i];
        } else if (arg == "--quiet") {
            quiet = true;
        } else if (arg == "--timeout-ms" && i + 1 < argc) {
            timeout_ms = static_cast<uint32_t>(std::stoul(argv[++i]));
        } else if (arg == "--help" || arg == "-h") {
            print_endorse_usage();
            return 0;
        } else {
            std::cerr << "Unknown option: " << arg << "\n";
            print_endorse_usage();
            return 2;
        }
    }

    // ── Build sign_request_payload ───────────────────────────────────────
    std::vector<uint8_t> wire_payload;

    if (!data_hex.empty()) {
        if (has_build_args) {
            std::cerr << "ERROR: --data-hex is mutually exclusive with builder options\n";
            return 2;
        }
        if (!is_hex_str(data_hex)) {
            std::cerr << "ERROR: --data-hex must be a valid hex string\n";
            return 2;
        }
        auto raw = hex_to_bytes(data_hex);
        size_t capacity = raw.size() + 32;
        for (int attempt = 0; attempt < 4; ++attempt) {
            wire_payload.assign(capacity, 0);
            UsefulBuf storage{wire_payload.data(), wire_payload.size()};
            QCBOREncodeContext ctx;
            QCBOREncode_Init(&ctx, storage);
            QCBOREncode_OpenArray(&ctx);
            QCBOREncode_OpenArray(&ctx);
            QCBOREncode_AddBytes(&ctx, UsefulBufC{raw.data(), raw.size()});
            QCBOREncode_CloseArray(&ctx);
            QCBOREncode_AddBool(&ctx, true);
            QCBOREncode_CloseArray(&ctx);
            UsefulBufC encoded{};
            QCBORError err = QCBOREncode_Finish(&ctx, &encoded);
            if (err == QCBOR_SUCCESS) {
                wire_payload.resize(encoded.len);
                break;
            }
            if (err != QCBOR_ERR_BUFFER_TOO_SMALL) {
                std::cerr << "ERROR: encode failed: " << qcbor_err_to_str(err) << "\n";
                return 2;
            }
            capacity *= 2;
        }
        std::cout << "Using raw data (" << raw.size() << " bytes, payload "
                  << wire_payload.size() << " bytes)\n";
    } else if (has_build_args) {
        if (org_id_hex.empty() || !is_hex_str(org_id_hex)) {
            std::cerr << "ERROR: --org-id is required (valid hex)\n";
            return 2;
        }
        if (org_pk_hex.empty() || !is_hex_str(org_pk_hex)) {
            std::cerr << "ERROR: --org-pk is required (valid hex)\n";
            return 2;
        }
        if (not_before_val <= 0) {
            not_before_val = static_cast<int64_t>(std::time(nullptr));
        }

        auto org_id = hex_to_bytes(org_id_hex);
        auto org_pk = hex_to_bytes(org_pk_hex);

        std::string build_error;
        if (!build_sign_request_payload(org_id, org_pk,
                                        static_cast<uint64_t>(not_before_val),
                                        static_cast<uint64_t>(not_after_val),
                                        wire_payload, build_error)) {
            std::cerr << "ERROR: failed to build endorsement payload: "
                      << build_error << "\n";
            return 2;
        }
        std::cout << "Built org-endorsement sign_request_payload ("
                  << wire_payload.size() << " bytes)\n";
    } else {
        std::cerr << "ERROR: provide either --data-hex or --org-id/--org-pk\n";
        print_endorse_usage();
        return 2;
    }

    // ── Transport ────────────────────────────────────────────────────────
    std::string transport_error;
    if (!configure_transport_for_command(cfg, transport_error)) {
        std::cerr << transport_error << "\n";
        return 2;
    }
    if (!swp_transport_open(cfg.port.c_str(), cfg.baud)) {
        std::cerr << "Failed to open serial port: " << cfg.port << "\n";
        return 2;
    }

    // Use FLAG_SIGN — same wire protocol as attestation requests
    const bool sent = swp_transport_send(
        wire_payload.data(),
        static_cast<uint32_t>(wire_payload.size()),
        static_cast<uint8_t>(FLAG_SIGN | FLAG_LAST_FRAME),
        ENCODING_CBOR);
    if (!sent) {
        std::cerr << "Failed to send endorse request\n";
        swp_transport_close();
        return 2;
    }

    std::vector<uint8_t> tree_response, att_response;
    swp_rx_meta_t tree_meta{}, att_meta{};
    std::string receive_error;
    if (!receive_endorse_responses(timeout_ms, tree_response, tree_meta,
                                   att_response, att_meta, receive_error)) {
        std::cerr << "Failed to receive response: " << receive_error << "\n";
        swp_transport_close();
        return 1;
    }

    // Check tree
    auto tc = classify_stardome_response_flag(tree_meta.flags, FLAG_STARDOME_TREE);
    if (tc == FrameClass::Error) {
        std::cerr << "Module tree error (flags=" << format_flag_hex(tree_meta.flags)
                  << "): " << bytes_to_hex(tree_response) << "\n";
        swp_transport_close();
        return 1;
    }
    if (tc == FrameClass::Unexpected) {
        std::cerr << "Unexpected tree response (flags="
                  << format_flag_hex(tree_meta.flags) << ")\n";
        swp_transport_close();
        return 1;
    }

    // Check attestation
    auto ac = classify_stardome_response_flag(att_meta.flags, FLAG_STARDOME_ATTESTATION);
    if (ac == FrameClass::Error) {
        std::cerr << "Module attestation error (flags=" << format_flag_hex(att_meta.flags)
                  << "): " << bytes_to_hex(att_response) << "\n";
        swp_transport_close();
        return 1;
    }
    if (ac == FrameClass::Unexpected) {
        std::cerr << "Unexpected attestation response (flags="
                  << format_flag_hex(att_meta.flags) << ")\n";
        swp_transport_close();
        return 1;
    }
    swp_transport_close();

    // ── Parse attestation ────────────────────────────────────────────────
    std::vector<uint8_t> merkle_root, xmss_sig, xmss_pk;
    std::string parse_error;
    if (!parse_attestation_fields(att_response, merkle_root, xmss_sig,
                                  xmss_pk, parse_error)) {
        std::cerr << "ERROR: failed to parse attestation: " << parse_error << "\n";
        return 2;
    }

    // ── Output ───────────────────────────────────────────────────────────
    auto mr_hex = hex_bytes_str(merkle_root);
    auto sig_hex = hex_bytes_str(xmss_sig);
    auto pk_hex = hex_bytes_str(xmss_pk);

    if (!quiet) {
        std::cout << "\nModule XMSS public key:\n"
                  << "  " << pk_hex << "\n\n"
                  << "Merkle root (" << merkle_root.size() << " bytes):\n"
                  << "  " << mr_hex << "\n\n"
                  << "XMSS signature (" << xmss_sig.size() << " bytes):\n"
                  << "  " << sig_hex << "\n\n"
                  << "Use with gen-bootstrap:\n"
                  << "  --module-merkle-root " << mr_hex << "\n"
                  << "  --module-signature " << sig_hex << "\n";
    }

    if (!out_tree.empty()) {
        std::ofstream of(out_tree, std::ios::binary | std::ios::trunc);
        if (of.is_open()) {
            of.write(reinterpret_cast<const char*>(tree_response.data()),
                     static_cast<std::streamsize>(tree_response.size()));
            std::cout << "Wrote tree to " << out_tree << "\n";
        }
    }
    if (!out_attestation.empty()) {
        std::ofstream of(out_attestation, std::ios::binary | std::ios::trunc);
        if (of.is_open()) {
            of.write(reinterpret_cast<const char*>(att_response.data()),
                     static_cast<std::streamsize>(att_response.size()));
            std::cout << "Wrote attestation to " << out_attestation << "\n";
        }
    }

    return 0;
}

} // namespace stardome