#pragma once

#include "app_config.hpp"
#include "swp_bridge.h"

#include <cstdint>
#include <string>
#include <vector>

namespace stardome {

enum class FrameClass {
    Expected,
    Error,
    Unexpected,
};

int run_simple_request(const AppConfig& cfg, uint8_t flag, const char* label);
bool send_request_and_receive(const AppConfig& cfg,
							  uint8_t flag,
							  std::vector<uint8_t>& response,
							  uint32_t timeout_ms = 5000);
bool send_request_and_receive_ex(const AppConfig& cfg,
								 uint8_t flag,
								 std::vector<uint8_t>& response,
								 swp_rx_meta_t* response_meta,
								 uint32_t timeout_ms = 5000);
bool send_payload_and_receive_ex(const AppConfig& cfg,
								 uint8_t flag,
								 const uint8_t* payload,
								 uint32_t payload_len,
								 std::vector<uint8_t>& response,
								 swp_rx_meta_t* response_meta,
								 uint32_t timeout_ms = 5000);
bool configure_transport_for_command(const AppConfig& cfg, std::string& error);

FrameClass classify_stardome_response_flag(uint8_t received_flags, uint8_t expected_base_flag);
bool is_stardome_error_flag(uint8_t received_flags);
std::string format_flag_hex(uint8_t flag);
std::string bytes_to_hex(const std::vector<uint8_t>& data);

int run_attestation_command(const AppConfig& cfg, int argc, char** argv);
int run_attestation_file_command(const AppConfig& cfg, int argc, char** argv);
int run_proof_command(const AppConfig& cfg, int argc, char** argv);
int run_status_command(const AppConfig& cfg, int argc, char** argv);
int run_id_command(const AppConfig& cfg, int argc, char** argv);
int run_lowmode_command(const AppConfig& cfg, int argc, char** argv);
int run_highmode_command(const AppConfig& cfg, int argc, char** argv);
int run_off_command(const AppConfig& cfg, int argc, char** argv);
int run_firmware_command(const AppConfig& cfg, int argc, char** argv);
int run_timestamp_command(const AppConfig& cfg, int argc, char** argv);
int run_bootlog_command(const AppConfig& cfg, int argc, char** argv);
int run_verify_command(const AppConfig& cfg, int argc, char** argv);

} // namespace stardome
