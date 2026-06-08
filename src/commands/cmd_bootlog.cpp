#include "commands/command_common.hpp"
#include "stardome_flags.h"

#include "qcbor/qcbor_common.h"
#include "qcbor/qcbor_spiffy_decode.h"

#include <cerrno>
#include <chrono>
#include <cctype>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <sys/stat.h>
#include <sys/types.h>
#include <vector>

namespace stardome {

namespace {

constexpr uint8_t kBootlogRequestPayload[] = {'B', 'L', 'O', 'G', 0x01u, 0x01u};

struct IdentityKey {
    std::string key;
    std::string source;
};

std::vector<uint8_t> useful_buf_to_vector(UsefulBufC bytes) {
    const auto* begin = reinterpret_cast<const uint8_t*>(bytes.ptr);
    return std::vector<uint8_t>(begin, begin + bytes.len);
}

void print_bootlog_usage() {
    std::cout
        << "Usage:\n"
        << "  stardome-client [options] bootlog [get] [--out <path> | --dir <dir>] [--print] [--no-append]\n"
        << "                                      [--timeout-ms <ms>] [--id-timeout-ms <ms>]\n"
        << "\n"
        << "Notes:\n"
        << "  - Sends STARDOME_DATA payload 424c4f470101 (BLOG\\x01\\x01)\n"
        << "  - Default append target is bootlogs/<device-key>.log\n"
        << "  - Device key order is installation_id, host_id, then port plus collection timestamp\n"
        << "  - --out appends to the selected file; existing logs are never truncated\n";
}

std::string utc_timestamp_compact(std::time_t when) {
    std::tm tm{};
    gmtime_r(&when, &tm);
    std::ostringstream oss;
    oss << std::put_time(&tm, "%Y%m%dT%H%M%SZ");
    return oss.str();
}

std::string utc_timestamp_entry(std::time_t when) {
    std::tm tm{};
    gmtime_r(&when, &tm);
    std::ostringstream oss;
    oss << std::put_time(&tm, "%Y-%m-%dT%H:%M:%SZ");
    return oss.str();
}

std::string sanitize_path_token(const std::string& value) {
    std::string out;
    out.reserve(value.size());
    for (char ch : value) {
        const unsigned char uch = static_cast<unsigned char>(ch);
        if (std::isalnum(uch) || ch == '-' || ch == '_' || ch == '.') {
            out.push_back(ch);
        } else {
            out.push_back('_');
        }
    }
    return out.empty() ? "unknown" : out;
}

bool mkdir_if_needed(const std::string& path, std::string& error) {
    struct stat st{};
    if (stat(path.c_str(), &st) == 0) {
        if ((st.st_mode & S_IFDIR) != 0) {
            return true;
        }
        error = "append directory path exists but is not a directory: " + path;
        return false;
    }

    if (mkdir(path.c_str(), 0775) == 0) {
        return true;
    }

    if (errno == EEXIST) {
        return true;
    }

    error = "failed to create append directory " + path + ": " + std::strerror(errno);
    return false;
}

bool decode_identity_response(const std::vector<uint8_t>& payload,
                              std::vector<uint8_t>& host_id,
                              std::vector<uint8_t>& installation_id) {
    if (payload.empty()) {
        return false;
    }

    QCBORDecodeContext decode_ctx;
    UsefulBufC encoded{payload.data(), payload.size()};
    QCBORDecode_Init(&decode_ctx, encoded, QCBOR_DECODE_MODE_NORMAL);

    QCBORItem map_item{};
    QCBORDecode_EnterMap(&decode_ctx, &map_item);
    if (QCBORDecode_GetError(&decode_ctx) != QCBOR_SUCCESS || map_item.uDataType != QCBOR_TYPE_MAP) {
        return false;
    }

    UsefulBufC fw_buf{};
    UsefulBufC host_id_buf{};
    UsefulBufC installation_id_buf{};
    uint64_t version = 0;

    QCBORDecode_GetByteStringInMapN(&decode_ctx, 1, &fw_buf);
    if (QCBORDecode_GetError(&decode_ctx) != QCBOR_SUCCESS) {
        return false;
    }

    QCBORDecode_GetByteStringInMapN(&decode_ctx, 2, &host_id_buf);
    if (QCBORDecode_GetError(&decode_ctx) != QCBOR_SUCCESS) {
        return false;
    }

    QCBORDecode_GetByteStringInMapN(&decode_ctx, 3, &installation_id_buf);
    const QCBORError install_id_err = QCBORDecode_GetAndResetError(&decode_ctx);
    if (install_id_err != QCBOR_SUCCESS && install_id_err != QCBOR_ERR_LABEL_NOT_FOUND) {
        return false;
    }

    QCBORDecode_GetUInt64InMapN(&decode_ctx, 4, &version);
    if (QCBORDecode_GetError(&decode_ctx) != QCBOR_SUCCESS) {
        return false;
    }

    QCBORDecode_ExitMap(&decode_ctx);
    if (QCBORDecode_Finish(&decode_ctx) != QCBOR_SUCCESS) {
        return false;
    }

    (void)fw_buf;
    (void)version;
    host_id = useful_buf_to_vector(host_id_buf);
    if (installation_id_buf.ptr != nullptr) {
        installation_id = useful_buf_to_vector(installation_id_buf);
    } else {
        installation_id.clear();
    }
    return true;
}

IdentityKey select_identity_key(const AppConfig& cfg, uint32_t id_timeout_ms, std::time_t collected_at) {
    std::vector<uint8_t> response;
    swp_rx_meta_t response_meta{};

    if (send_payload_and_receive_ex(cfg, FLAG_STARDOME_ID, nullptr, 0, response, &response_meta, id_timeout_ms)) {
        const FrameClass frame_class = classify_stardome_response_flag(response_meta.flags, FLAG_STARDOME_ID_DATA);
        if (frame_class == FrameClass::Expected) {
            std::vector<uint8_t> host_id;
            std::vector<uint8_t> installation_id;
            if (decode_identity_response(response, host_id, installation_id)) {
                if (!installation_id.empty()) {
                    return {bytes_to_hex(installation_id), "installation_id"};
                }
                if (!host_id.empty()) {
                    return {bytes_to_hex(host_id), "host_id"};
                }
            } else if (!response.empty()) {
                return {bytes_to_hex(response), "host_id_legacy"};
            }
        }
    }

    return {sanitize_path_token(cfg.port) + "_" + utc_timestamp_compact(collected_at), "port_timestamp"};
}

const char* decode_stardome_data_error_reason(uint8_t code) {
    switch (code) {
        case 0x01: return "empty payload";
        case 0x02: return "staged source read failure";
        case 0x0B: return "unsupported/unknown STARDOME_DATA payload type";
        case 0x0C: return "bootlog read/send I/O failure";
        case 0x0D: return "first-boot identity gate active";
        case 0x03: return "file open failed";
        case 0x04: return "descriptor invalid/not found (legacy OTA-only routing)";
        case 0x05: return "size mismatch/out of range";
        case 0x06: return "flash erase failed";
        case 0x07: return "flash write failed";
        case 0x08: return "verify failed";
        case 0x09: return "vector sanity failed";
        case 0x0A: return "bank swap failed";
        default: return nullptr;
    }
}

bool append_bootlog_file(const std::string& path,
                         const std::vector<uint8_t>& bootlog,
                         const AppConfig& cfg,
                         const IdentityKey& identity,
                         const std::string& collected_utc,
                         std::string& error) {
    std::ofstream out(path, std::ios::binary | std::ios::app);
    if (!out.is_open()) {
        error = "failed to open append target: " + path;
        return false;
    }

    out << "\n=== bootlog " << collected_utc
        << " port=" << cfg.port
        << " key=" << identity.key
        << " key_source=" << identity.source
        << " ===\n";
    if (!bootlog.empty()) {
        out.write(reinterpret_cast<const char*>(bootlog.data()), static_cast<std::streamsize>(bootlog.size()));
        if (bootlog.back() != '\n') {
            out << "\n";
        }
    }

    if (!out.good()) {
        error = "failed while appending bootlog target: " + path;
        return false;
    }
    return true;
}

} // namespace

int run_bootlog_command(const AppConfig& cfg, int argc, char** argv) {
    int option_start = 0;
    if (argc > 0) {
        const std::string subcommand = argv[0];
        if (subcommand == "--help" || subcommand == "-h") {
            print_bootlog_usage();
            return 0;
        }
        if (subcommand == "get") {
            option_start = 1;
        } else {
            std::cerr << "Unknown bootlog subcommand: " << subcommand << "\n";
            print_bootlog_usage();
            return 2;
        }
    }

    std::string out_path;
    std::string out_dir = "bootlogs";
    bool append = true;
    bool print_payload = false;
    uint32_t timeout_ms = 5000;
    uint32_t id_timeout_ms = 1000;

    for (int i = option_start; i < argc; ++i) {
        const std::string arg = argv[i];
        if (arg == "--help" || arg == "-h") {
            print_bootlog_usage();
            return 0;
        }
        if (arg == "--out" && i + 1 < argc) {
            out_path = argv[++i];
        } else if (arg == "--dir" && i + 1 < argc) {
            out_dir = argv[++i];
        } else if (arg == "--print") {
            print_payload = true;
        } else if (arg == "--no-append") {
            append = false;
        } else if (arg == "--timeout-ms" && i + 1 < argc) {
            timeout_ms = static_cast<uint32_t>(std::strtoul(argv[++i], nullptr, 10));
        } else if (arg == "--id-timeout-ms" && i + 1 < argc) {
            id_timeout_ms = static_cast<uint32_t>(std::strtoul(argv[++i], nullptr, 10));
        } else {
            std::cerr << "Unknown option for bootlog: " << arg << "\n";
            print_bootlog_usage();
            return 2;
        }
    }

    if (!append && !print_payload) {
        print_payload = true;
    }

    const std::time_t collected_at = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
    const std::string collected_utc = utc_timestamp_entry(collected_at);
    IdentityKey identity = select_identity_key(cfg, id_timeout_ms, collected_at);

    std::vector<uint8_t> response;
    swp_rx_meta_t response_meta{};
    if (!send_payload_and_receive_ex(cfg,
                                     FLAG_STARDOME_DATA,
                                     kBootlogRequestPayload,
                                     static_cast<uint32_t>(sizeof(kBootlogRequestPayload)),
                                     response,
                                     &response_meta,
                                     timeout_ms)) {
        std::cerr << "Timeout waiting for bootlog response\n";
        return 1;
    }

    const FrameClass frame_class = classify_stardome_response_flag(response_meta.flags, FLAG_STARDOME_DATA);
    if (frame_class == FrameClass::Error) {
        std::cerr << "Device reported bootlog error (flags=" << format_flag_hex(response_meta.flags);
        if (!response.empty()) {
            const uint8_t err_code = response[0];
            const char* reason = decode_stardome_data_error_reason(err_code);
            std::cerr << ", code=0x" << std::uppercase << std::hex << std::setw(2) << std::setfill('0')
                      << static_cast<unsigned>(err_code) << std::dec;
            if (reason != nullptr) {
                std::cerr << ", reason=" << reason;
            }
        }
        std::cerr << "): " << bytes_to_hex(response) << "\n";
        return 1;
    }
    if (frame_class == FrameClass::Unexpected) {
        std::cerr << "Unexpected bootlog response frame (flags=" << format_flag_hex(response_meta.flags)
                  << ", payload=" << response.size() << " bytes)\n";
        return 1;
    }

    std::string append_path;
    if (append) {
        if (!out_path.empty()) {
            append_path = out_path;
        } else {
            std::string dir_error;
            if (!mkdir_if_needed(out_dir, dir_error)) {
                std::cerr << "Bootlog append failed: " << dir_error << "\n";
                return 1;
            }
            append_path = out_dir + "/" + sanitize_path_token(identity.key) + ".log";
        }

        std::string append_error;
        if (!append_bootlog_file(append_path, response, cfg, identity, collected_utc, append_error)) {
            std::cerr << "Bootlog append failed: " << append_error << "\n";
            return 1;
        }
    }

    std::cout << "BOOTLOG_BYTES " << response.size() << "\n";
    std::cout << "BOOTLOG_KEY_SOURCE " << identity.source << "\n";
    std::cout << "BOOTLOG_KEY " << identity.key << "\n";
    if (append) {
        std::cout << "BOOTLOG_APPENDED " << append_path << "\n";
    }

    if (print_payload) {
        std::cout.write(reinterpret_cast<const char*>(response.data()), static_cast<std::streamsize>(response.size()));
        if (!response.empty() && response.back() != '\n') {
            std::cout << "\n";
        }
    }

    return 0;
}

} // namespace stardome
