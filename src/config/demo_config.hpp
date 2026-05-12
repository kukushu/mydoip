#pragma once

#include <cstdint>

namespace config {

// DoIP transport
constexpr uint16_t kDoipPort = 13400;
constexpr uint8_t kDoipProtocolVersion = 0x02;
constexpr uint16_t kDoipPayloadTypeDiagnosticMessage = 0x8001;

// Logical addresses used by demo apps
constexpr uint16_t kTesterAddress = 0x0E00;
constexpr uint16_t kEcuAddress = 0x1001;

// Demo DCM data
constexpr uint16_t kVinDid = 0xF190;
constexpr uint16_t kSupportedRoutineId = 0xFF00;

}  // namespace config
