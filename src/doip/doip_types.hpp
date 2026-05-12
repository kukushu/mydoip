#pragma once

#include "../config/demo_config.hpp"

#include <cstdint>

namespace doip {


struct Header {
    uint8_t protocolVersion{config::kDoipProtocolVersion};
    uint8_t inverseVersion{static_cast<uint8_t>(~config::kDoipProtocolVersion)};
    uint16_t payloadType{config::kDoipPayloadTypeDiagnosticMessage};
    uint32_t payloadLength{0};
};

struct DiagnosticMessage {
    uint16_t sourceAddress{0};
    uint16_t targetAddress{0};
};

}  // namespace doip
