#include "doip_frame.hpp"

#include <arpa/inet.h>
#include <cstring>

namespace doip {

bool encodeFrame(const Frame& frame, std::vector<uint8_t>& out) {
    out.clear();
    out.reserve(8 + frame.payload.size());
    out.push_back(frame.header.protocolVersion);
    out.push_back(frame.header.inverseVersion);
    const uint16_t pt = htons(frame.header.payloadType);
    const uint32_t len = htonl(static_cast<uint32_t>(frame.payload.size()));
    out.insert(out.end(), reinterpret_cast<const uint8_t*>(&pt), reinterpret_cast<const uint8_t*>(&pt) + 2);
    out.insert(out.end(), reinterpret_cast<const uint8_t*>(&len), reinterpret_cast<const uint8_t*>(&len) + 4);
    out.insert(out.end(), frame.payload.begin(), frame.payload.end());
    return true;
}

bool decodeFrame(const std::vector<uint8_t>& data, Frame& out) {
    if (data.size() < 8) return false;
    out.header.protocolVersion = data[0];
    out.header.inverseVersion = data[1];
    if (out.header.inverseVersion != static_cast<uint8_t>(~out.header.protocolVersion)) return false;
    std::memcpy(&out.header.payloadType, data.data() + 2, 2);
    std::memcpy(&out.header.payloadLength, data.data() + 4, 4);
    out.header.payloadType = ntohs(out.header.payloadType);
    out.header.payloadLength = ntohl(out.header.payloadLength);
    if (data.size() != out.header.payloadLength + 8) return false;
    out.payload.assign(data.begin() + 8, data.end());
    return true;
}

}  // namespace doip
