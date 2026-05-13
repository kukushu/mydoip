#pragma once

#include <cstdint>

namespace uds {

constexpr uint8_t kNrcGeneralReject = 0x10;
constexpr uint8_t kNrcSubFunctionNotSupported = 0x12;
constexpr uint8_t kNrcIncorrectMessageLengthOrInvalidFormat = 0x13;
constexpr uint8_t kNrcRequestOutOfRange = 0x31;
constexpr uint8_t kNrcSecurityAccessDenied = 0x33;
constexpr uint8_t kNrcInvalidKey = 0x35;
constexpr uint8_t kNrcServiceNotSupported = 0x11;

}  // namespace uds
