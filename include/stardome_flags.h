#pragma once

#include <cstdint>

namespace stardome {

constexpr uint8_t FLAG_LAST_FRAME = 0x01;
constexpr uint8_t FLAG_SIGN = 0x02;
constexpr uint8_t FLAG_SIGN_FILE = 0x22;
constexpr uint8_t FLAG_STARDOME_ATTESTATION = 0x04;
constexpr uint8_t FLAG_STARDOME_PROOF = 0x08;
constexpr uint8_t FLAG_STARDOME_STATUS = 0x10;
constexpr uint8_t FLAG_STARDOME_DATA = 0x12;
constexpr uint8_t FLAG_STARDOME_TREE = 0x20;
constexpr uint8_t FLAG_STARDOME_ID = 0x40;
constexpr uint8_t FLAG_STARDOME_LOWMODE = 0x50;
constexpr uint8_t FLAG_STARDOME_HIGHMODE = 0x70;
constexpr uint8_t FLAG_STARDOME_OFF = 0x80;
constexpr uint8_t FLAG_STARDOME_STATUS_DATA = 0x90;
constexpr uint8_t FLAG_STARDOME_ID_DATA = 0xB0;
constexpr uint8_t FLAG_STARDOME_PROOF_DATA = 0xB2;
constexpr uint8_t FLAG_SIGN_ERROR = 0xC2;
constexpr uint8_t FLAG_STARDOME_PROOF_ERROR = 0xC4;
constexpr uint8_t FLAG_STARDOME_DATA_ERROR = 0xC6;
constexpr uint8_t FLAG_STARDOME_STATUS_ERROR = 0xC8;
constexpr uint8_t FLAG_STARDOME_ID_ERROR = 0xCC;
constexpr uint8_t FLAG_STARDOME_OFF_ERROR = 0xCE;
constexpr uint8_t FLAG_STARDOME_LOWMODE_ERROR = 0xD8;
constexpr uint8_t FLAG_STARDOME_HIGHMODE_ERROR = 0xDA;

constexpr uint8_t ENCODING_BINARY = 0x00;
constexpr uint8_t ENCODING_ASCII = 0x01;
constexpr uint8_t ENCODING_UTF8 = 0x02;
constexpr uint8_t ENCODING_JSON = 0x03;
constexpr uint8_t ENCODING_CBOR = 0x04;

} // namespace stardome
