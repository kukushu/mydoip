#pragma once

#include "doip_frame.hpp"
#include "iuds_server.hpp"

#include <cstdint>

namespace doip {

enum class DoipConnectionState { Disconnected, TcpConnected, RoutingActivated, Closing };

class DoipConnection {
public:
    DoipConnection(int socketFd, IUdsServer& udsServer);
    bool run();

private:
    bool readOneFrame(Frame& frame);
    bool sendFrame(uint16_t payloadType, const std::vector<uint8_t>& payload);
    bool handleRoutingActivation(const Frame& frame);
    bool handleDiagnosticMessage(const Frame& frame);
    bool handleAliveCheck(const Frame& frame);
    bool isSourceAddressAllowed(uint16_t sa) const;
    bool isActivationTypeAllowed(uint8_t activationType) const;

    int socketFd_;
    IUdsServer& udsServer_;
    DoipConnectionState state_{DoipConnectionState::TcpConnected};
    uint16_t testerAddress_{0};
};

}  // namespace doip
