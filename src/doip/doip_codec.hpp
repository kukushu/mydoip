#pragma once

#include "doip_types.hpp"

#include <arpa/inet.h>
#include <cstdint>
#include <cstring>
#include <vector>

namespace doip {

inline std::vector<uint8_t> encodeDiagnosticFrame(uint16_t srcAddr, uint16_t tgtAddr,
                                                   const std::vector<uint8_t>& udsPayload) {
    std::vector<uint8_t> payload;
    payload.reserve(4 + udsPayload.size());

    const uint16_t srcN = htons(srcAddr);
    const uint16_t tgtN = htons(tgtAddr);
    payload.insert(payload.end(), reinterpret_cast<const uint8_t*>(&srcN), reinterpret_cast<const uint8_t*>(&srcN) + 2);
    payload.insert(payload.end(), reinterpret_cast<const uint8_t*>(&tgtN), reinterpret_cast<const uint8_t*>(&tgtN) + 2);
    payload.insert(payload.end(), udsPayload.begin(), udsPayload.end());

    Header header;
    header.payloadLength = static_cast<uint32_t>(payload.size());

    std::vector<uint8_t> frame;
    frame.reserve(8 + payload.size());
    frame.push_back(header.protocolVersion);
    frame.push_back(header.inverseVersion);

    const uint16_t payloadTypeN = htons(header.payloadType);
    const uint32_t payloadLengthN = htonl(header.payloadLength);
    frame.insert(frame.end(), reinterpret_cast<const uint8_t*>(&payloadTypeN), reinterpret_cast<const uint8_t*>(&payloadTypeN) + 2);
    frame.insert(frame.end(), reinterpret_cast<const uint8_t*>(&payloadLengthN), reinterpret_cast<const uint8_t*>(&payloadLengthN) + 4);
    frame.insert(frame.end(), payload.begin(), payload.end());

    return frame;
}

inline bool decodeDiagnosticFrame(const std::vector<uint8_t>& frame, DiagnosticMessage& info,
                                  std::vector<uint8_t>& udsPayload) {
    if (frame.size() < 12) return false;

    const uint8_t version = frame[0];
    const uint8_t inverse = frame[1];
    if (inverse != static_cast<uint8_t>(~version)) return false;

    uint16_t payloadTypeN = 0;
    uint32_t payloadLengthN = 0;
    std::memcpy(&payloadTypeN, &frame[2], 2);
    std::memcpy(&payloadLengthN, &frame[4], 4);

    const uint16_t payloadType = ntohs(payloadTypeN);
    const uint32_t payloadLength = ntohl(payloadLengthN);
    if (payloadType != kPayloadTypeDiagnosticMessage) return false;
    if (payloadLength + 8 != frame.size()) return false;

    uint16_t srcN = 0;
    uint16_t tgtN = 0;
    std::memcpy(&srcN, &frame[8], 2);
    std::memcpy(&tgtN, &frame[10], 2);
    info.sourceAddress = ntohs(srcN);
    info.targetAddress = ntohs(tgtN);

    udsPayload.assign(frame.begin() + 12, frame.end());
    return true;
}

}  // namespace doip
