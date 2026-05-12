#pragma once

#include "../config/demo_config.hpp"

#include <cstdint>

namespace doip {

constexpr uint16_t kPort = config::kDoipPort;
constexpr uint16_t kPayloadTypeDiagnosticMessage = config::kDoipPayloadTypeDiagnosticMessage;
constexpr uint8_t kProtocolVersion = config::kDoipProtocolVersion;

struct Header {
    uint8_t protocolVersion{kProtocolVersion};
    uint8_t inverseVersion{static_cast<uint8_t>(~kProtocolVersion)};
    uint16_t payloadType{kPayloadTypeDiagnosticMessage};
    uint32_t payloadLength{0};
};

struct DiagnosticMessage {
    uint16_t sourceAddress{0};
    uint16_t targetAddress{0};
};

}  // namespace doip
