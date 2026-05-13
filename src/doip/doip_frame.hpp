#pragma once

#include "../config/demo_config.hpp"

#include <cstdint>
#include <vector>

namespace doip {

enum class PayloadType : uint16_t {
    RoutingActivationRequest = 0x0005,
    RoutingActivationResponse = 0x0006,
    AliveCheckRequest = 0x0007,
    AliveCheckResponse = 0x0008,
    DiagnosticMessage = 0x8001,
};

struct Header {
    uint8_t protocolVersion{config::kDoipProtocolVersion};
    uint8_t inverseVersion{static_cast<uint8_t>(~config::kDoipProtocolVersion)};
    uint16_t payloadType{0};
    uint32_t payloadLength{0};
};

struct Frame {
    Header header;
    std::vector<uint8_t> payload;
};

bool encodeFrame(const Frame& frame, std::vector<uint8_t>& out);
bool decodeFrame(const std::vector<uint8_t>& data, Frame& out);

}  // namespace doip
