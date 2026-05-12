#include "doip_connection.hpp"

#include "../config/demo_config.hpp"
#include "socket_io.hpp"

#include <arpa/inet.h>
#include <cstring>
#include <unistd.h>

namespace doip {
namespace {
constexpr uint8_t kRaOk = 0x10;
constexpr uint8_t kRaDeniedUnknownSourceAddress = 0x00;
constexpr uint8_t kRaDeniedUnsupportedActivationType = 0x06;
constexpr uint8_t kRaDeniedRoutingNotActive = 0x11;
}  // namespace

DoipConnection::DoipConnection(int socketFd, IUdsServer& udsServer) : socketFd_(socketFd), udsServer_(udsServer) {}

bool DoipConnection::readOneFrame(Frame& frame) {
    uint8_t header[8];
    if (!recvAll(socketFd_, header, 8)) return false;
    uint32_t lenN = 0;
    std::memcpy(&lenN, &header[4], 4);
    const uint32_t len = ntohl(lenN);
    std::vector<uint8_t> raw(8 + len);
    std::memcpy(raw.data(), header, 8);
    if (!recvAll(socketFd_, raw.data() + 8, len)) return false;
    return decodeFrame(raw, frame);
}

bool DoipConnection::sendFrame(uint16_t payloadType, const std::vector<uint8_t>& payload) {
    Frame frame{};
    frame.header.payloadType = payloadType;
    frame.payload = payload;
    std::vector<uint8_t> raw;
    encodeFrame(frame, raw);
    return sendAll(socketFd_, raw.data(), raw.size());
}

bool DoipConnection::isSourceAddressAllowed(uint16_t sa) const {
    return sa >= 0x0E00 && sa <= 0x0EFF;
}

bool DoipConnection::isActivationTypeAllowed(uint8_t activationType) const { return activationType == 0x00; }

bool DoipConnection::handleRoutingActivation(const Frame& frame) {
    if (frame.payload.size() < 7) return false;
    uint16_t sa = static_cast<uint16_t>(frame.payload[0] << 8 | frame.payload[1]);
    uint8_t activationType = frame.payload[2];

    uint8_t code = kRaOk;
    if (!isSourceAddressAllowed(sa)) {
        code = kRaDeniedUnknownSourceAddress;
    } else if (!isActivationTypeAllowed(activationType)) {
        code = kRaDeniedUnsupportedActivationType;
    }

    std::vector<uint8_t> resp(9, 0x00);
    resp[0] = frame.payload[0];
    resp[1] = frame.payload[1];
    resp[2] = static_cast<uint8_t>((config::kEcuAddress >> 8) & 0xFF);
    resp[3] = static_cast<uint8_t>(config::kEcuAddress & 0xFF);
    resp[4] = code;

    if (code == kRaOk) {
        testerAddress_ = sa;
        state_ = DoipConnectionState::RoutingActivated;
    }
    return sendFrame(static_cast<uint16_t>(PayloadType::RoutingActivationResponse), resp);
}

bool DoipConnection::handleDiagnosticMessage(const Frame& frame) {
    if (state_ != DoipConnectionState::RoutingActivated) {
        std::vector<uint8_t> nack = {kRaDeniedRoutingNotActive};
        return sendFrame(static_cast<uint16_t>(PayloadType::AliveCheckResponse), nack);
    }
    if (frame.payload.size() < 4) return false;
    uint16_t sa = static_cast<uint16_t>(frame.payload[0] << 8 | frame.payload[1]);
    uint16_t ta = static_cast<uint16_t>(frame.payload[2] << 8 | frame.payload[3]);
    std::vector<uint8_t> uds(frame.payload.begin() + 4, frame.payload.end());

    const std::vector<uint8_t> udsResp = udsServer_.processUdsRequest(sa, ta, uds);
    std::vector<uint8_t> payload;
    payload.push_back(static_cast<uint8_t>((ta >> 8) & 0xFF));
    payload.push_back(static_cast<uint8_t>(ta & 0xFF));
    payload.push_back(static_cast<uint8_t>((sa >> 8) & 0xFF));
    payload.push_back(static_cast<uint8_t>(sa & 0xFF));
    payload.insert(payload.end(), udsResp.begin(), udsResp.end());
    return sendFrame(static_cast<uint16_t>(PayloadType::DiagnosticMessage), payload);
}

bool DoipConnection::handleAliveCheck(const Frame& frame) {
    if (frame.header.payloadType == static_cast<uint16_t>(PayloadType::AliveCheckRequest)) {
        std::vector<uint8_t> resp(2, 0x00);
        resp[0] = static_cast<uint8_t>((testerAddress_ >> 8) & 0xFF);
        resp[1] = static_cast<uint8_t>(testerAddress_ & 0xFF);
        return sendFrame(static_cast<uint16_t>(PayloadType::AliveCheckResponse), resp);
    }
    return true;
}

bool DoipConnection::run() {
    while (state_ != DoipConnectionState::Closing) {
        Frame frame;
        if (!readOneFrame(frame)) break;
        const uint16_t pt = frame.header.payloadType;
        bool ok = true;
        if (pt == static_cast<uint16_t>(PayloadType::RoutingActivationRequest)) {
            ok = handleRoutingActivation(frame);
        } else if (pt == static_cast<uint16_t>(PayloadType::DiagnosticMessage)) {
            ok = handleDiagnosticMessage(frame);
        } else if (pt == static_cast<uint16_t>(PayloadType::AliveCheckRequest) ||
                   pt == static_cast<uint16_t>(PayloadType::AliveCheckResponse)) {
            ok = handleAliveCheck(frame);
        }
        if (!ok) break;
    }
    close(socketFd_);
    state_ = DoipConnectionState::Disconnected;
    return true;
}

}  // namespace doip
