#include "commands/command_common.hpp"
#include "stardome_flags.h"

#include "qcbor/qcbor_common.h"
#include "qcbor/qcbor_spiffy_decode.h"

#include <cctype>
#include <iostream>
#include <optional>
#include <string>
#include <vector>

namespace stardome {

namespace {

std::vector<uint8_t> useful_buf_to_vector(UsefulBufC bytes) {
    const auto* begin = reinterpret_cast<const uint8_t*>(bytes.ptr);
    return std::vector<uint8_t>(begin, begin + bytes.len);
}

void print_host_id_usage() {
    std::cout
        << "Usage:\n"
    << "  stardome-client [options] id get\n"
    << "  stardome-client [options] id set --hex <bytes_hex>\n"
        << "\n"
        << "Notes:\n"
    << "  - id with no subcommand defaults to 'get'\n"
        << "  - --hex accepts optional 0x prefix and ignores spaces\n"
        << "  - set payload must be 1..1024 bytes\n";
}

bool parse_hex_payload(const std::string& input, std::vector<uint8_t>& out, std::string& error) {
    std::string hex;
    hex.reserve(input.size());

    for (char ch : input) {
        if (!std::isspace(static_cast<unsigned char>(ch))) {
            hex.push_back(ch);
        }
    }

    if (hex.size() >= 2 && hex[0] == '0' && (hex[1] == 'x' || hex[1] == 'X')) {
        hex.erase(0, 2);
    }

    if (hex.empty()) {
        error = "hex payload is empty";
        return false;
    }
    if (hex.size() % 2 != 0) {
        error = "hex payload length must be even";
        return false;
    }

    auto hex_nibble = [](char ch) -> int {
        if (ch >= '0' && ch <= '9') return ch - '0';
        if (ch >= 'a' && ch <= 'f') return 10 + (ch - 'a');
        if (ch >= 'A' && ch <= 'F') return 10 + (ch - 'A');
        return -1;
    };

    out.clear();
    out.reserve(hex.size() / 2);
    for (size_t i = 0; i < hex.size(); i += 2) {
        const int hi = hex_nibble(hex[i]);
        const int lo = hex_nibble(hex[i + 1]);
        if (hi < 0 || lo < 0) {
            error = "hex payload contains non-hex characters";
            out.clear();
            return false;
        }
        out.push_back(static_cast<uint8_t>((hi << 4) | lo));
    }

    return true;
}

bool decode_host_id_response_strict(const std::vector<uint8_t>& payload,
                                    std::string& fw,
                                    std::vector<uint8_t>& host_id,
                                    std::vector<uint8_t>& installation_id,
                                    uint64_t& version,
                                    std::string& error) {
    if (payload.empty()) {
        error = "empty payload";
        return false;
    }

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
        error = "id response must be a CBOR map";
        return false;
    }

    UsefulBufC fw_buf{};
    UsefulBufC host_id_buf{};
    UsefulBufC installation_id_buf{};

    QCBORDecode_GetByteStringInMapN(&decode_ctx, 1, &fw_buf);
    if (QCBORDecode_GetError(&decode_ctx) != QCBOR_SUCCESS) {
        error = "missing/invalid fw key(1)";
        return false;
    }

    QCBORDecode_GetByteStringInMapN(&decode_ctx, 2, &host_id_buf);
    if (QCBORDecode_GetError(&decode_ctx) != QCBOR_SUCCESS) {
        error = "missing/invalid host_id key(2)";
        return false;
    }

    QCBORDecode_GetByteStringInMapN(&decode_ctx, 3, &installation_id_buf);
    const QCBORError install_id_err = QCBORDecode_GetAndResetError(&decode_ctx);
    if (install_id_err != QCBOR_SUCCESS && install_id_err != QCBOR_ERR_LABEL_NOT_FOUND) {
        error = "invalid installation_id key(3)";
        return false;
    }

    QCBORDecode_GetUInt64InMapN(&decode_ctx, 4, &version);
    if (QCBORDecode_GetError(&decode_ctx) != QCBOR_SUCCESS) {
        error = "missing/invalid response_version key(4)";
        return false;
    }

    QCBORDecode_ExitMap(&decode_ctx);

    const QCBORError finish_error = QCBORDecode_Finish(&decode_ctx);
    if (finish_error != QCBOR_SUCCESS) {
        error = qcbor_err_to_str(finish_error);
        return false;
    }

    fw = std::string(reinterpret_cast<const char*>(fw_buf.ptr), fw_buf.len);
    host_id = useful_buf_to_vector(host_id_buf);
    if (installation_id_buf.ptr != nullptr) {
        installation_id = useful_buf_to_vector(installation_id_buf);
    } else {
        installation_id.clear();
    }
    return true;
}

bool is_printable_text(const std::vector<uint8_t>& bytes, std::string& out) {
    if (bytes.empty()) {
        return false;
    }

    out.assign(bytes.begin(), bytes.end());
    for (char ch : out) {
        const unsigned char uch = static_cast<unsigned char>(ch);
        const bool printable_ascii = (uch > 31u && uch < 127u);
        const bool allowed_ws = (ch == '\r' || ch == '\n' || ch == '\t');
        if (!printable_ascii && !allowed_ws) {
            return false;
        }
    }
    return true;
}

} // namespace

int run_id_command(const AppConfig& cfg, int argc, char** argv) {
    enum class Mode {
        Get,
        Set,
    };

    Mode mode = Mode::Get;
    int option_start = 0;

    if (argc > 0) {
        const std::string subcommand = argv[0];
        if (subcommand == "--help" || subcommand == "-h") {
            print_host_id_usage();
            return 0;
        }
        if (subcommand == "get") {
            mode = Mode::Get;
            option_start = 1;
        } else if (subcommand == "set") {
            mode = Mode::Set;
            option_start = 1;
        } else {
            std::cerr << "Unknown id subcommand: " << subcommand << "\n";
            print_host_id_usage();
            return 2;
        }
    }

    std::string set_hex;
    for (int i = option_start; i < argc; ++i) {
        const std::string arg = argv[i];
        if (arg == "--help" || arg == "-h") {
            print_host_id_usage();
            return 0;
        }
        if (mode == Mode::Set && arg == "--hex" && i + 1 < argc) {
            set_hex = argv[++i];
            continue;
        }

        std::cerr << "Unknown option for id: " << arg << "\n";
        print_host_id_usage();
        return 2;
    }

    std::vector<uint8_t> request_payload;
    if (mode == Mode::Set) {
        if (set_hex.empty()) {
            std::cerr << "Missing required argument: --hex <bytes_hex>\n";
            return 2;
        }
        std::string parse_error;
        if (!parse_hex_payload(set_hex, request_payload, parse_error)) {
            std::cerr << "Invalid --hex payload: " << parse_error << "\n";
            return 2;
        }
        if (request_payload.empty() || request_payload.size() > 1024) {
            std::cerr << "id set payload must be 1..1024 bytes (got "
                      << request_payload.size() << ")\n";
            return 2;
        }
    }

    std::vector<uint8_t> response;
    swp_rx_meta_t response_meta{};
    const uint8_t* payload_ptr = request_payload.empty() ? nullptr : request_payload.data();
    const uint32_t payload_len = static_cast<uint32_t>(request_payload.size());
    if (!send_payload_and_receive_ex(cfg,
                                     FLAG_STARDOME_ID,
                                     payload_ptr,
                                     payload_len,
                                     response,
                                     &response_meta,
                                     5000)) {
        std::cerr << "Timeout waiting for id response\n";
        return 1;
    }

    const FrameClass frame_class = classify_stardome_response_flag(response_meta.flags, FLAG_STARDOME_ID_DATA);
    if (frame_class == FrameClass::Error) {
        std::cerr << "Device reported id error (flags=" << format_flag_hex(response_meta.flags)
                  << "): " << bytes_to_hex(response) << "\n";
        return 1;
    }
    if (frame_class == FrameClass::Unexpected) {
        std::cerr << "Unexpected id response frame (flags=" << format_flag_hex(response_meta.flags)
                  << ", payload=" << response.size() << " bytes)\n";
        return 1;
    }

    std::vector<uint8_t> host_id;
    std::vector<uint8_t> installation_id;
    std::optional<uint64_t> version;
    std::string fw;
    std::string decode_error;
    uint64_t strict_version = 0;
    if (decode_host_id_response_strict(response, fw, host_id, installation_id, strict_version, decode_error)) {
        version = strict_version;
    } else {
        fw.clear();
        host_id = response;
        installation_id.clear();
    }

    if (mode == Mode::Set) {
        std::cout << "ID_SET_BYTES " << request_payload.size() << "\n";
    }
    if (version.has_value()) {
        std::cout << "FW " << fw << "\n";
    }
    std::cout << "HOST_ID len=" << host_id.size() << "\n";
    std::cout << "HOST_ID hex=" << bytes_to_hex(host_id) << "\n";
    if (version.has_value()) {
        if (!installation_id.empty()) {
            std::cout << "INSTALLATION_ID len=" << installation_id.size() << "\n";
            std::cout << "INSTALLATION_ID hex=" << bytes_to_hex(installation_id) << "\n";
        } else {
            std::cout << "INSTALLATION_ID <missing>\n";
        }
        std::cout << "HOST_ID_RESPONSE_VERSION " << *version << "\n";
    }

    std::string printable_text;
    if (is_printable_text(host_id, printable_text)) {
        std::cout << "HOST_ID text='" << printable_text << "'\n";
    }

    return 0;
}

} // namespace stardome
