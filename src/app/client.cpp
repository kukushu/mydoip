#include "../doip/doip_codec.hpp"
#include "../doip/socket_io.hpp"
#include "../uds/uds_types.hpp"
#include "../uds/uds_utils.hpp"

#include <arpa/inet.h>
#include <cstring>
#include <iostream>
#include <sys/socket.h>
#include <unistd.h>

int main() {
    int clientFd = socket(AF_INET, SOCK_STREAM, 0);
    if (clientFd < 0) {
        std::cerr << "socket create failed\n";
        return 1;
    }

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(doip::kPort);
    inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);

    if (connect(clientFd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
        std::cerr << "connect failed\n";
        return 1;
    }

    constexpr uint16_t kTesterAddress = 0x0E00;
    constexpr uint16_t kEcuAddress = 0x1001;

    const uds::Message udsRequest = {uds::kSidReadDataByIdentifier, 0xF1, 0x90};
    std::vector<uint8_t> requestFrame = doip::encodeDiagnosticFrame(kTesterAddress, kEcuAddress, udsRequest);

    std::cout << "Tx UDS request: " << uds::bytesToHex(udsRequest) << "\n";
    if (!doip::sendAll(clientFd, requestFrame.data(), requestFrame.size())) {
        std::cerr << "send request failed\n";
        return 1;
    }

    uint8_t header[8];
    if (!doip::recvAll(clientFd, header, 8)) {
        std::cerr << "recv header failed\n";
        return 1;
    }

    uint32_t payloadLenN = 0;
    std::memcpy(&payloadLenN, &header[4], 4);
    const uint32_t payloadLen = ntohl(payloadLenN);

    std::vector<uint8_t> responseFrame(8 + payloadLen);
    std::memcpy(responseFrame.data(), header, 8);
    if (!doip::recvAll(clientFd, responseFrame.data() + 8, payloadLen)) {
        std::cerr << "recv payload failed\n";
        return 1;
    }

    doip::DiagnosticMessage meta;
    uds::Message udsResponse;
    if (!doip::decodeDiagnosticFrame(responseFrame, meta, udsResponse)) {
        std::cerr << "invalid doip frame\n";
        return 1;
    }

    std::cout << "Rx UDS response from ecu 0x" << std::hex << meta.sourceAddress
              << ": " << uds::bytesToHex(udsResponse) << std::dec << "\n";

    close(clientFd);
    return 0;
}
