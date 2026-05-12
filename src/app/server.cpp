#include "../dcm/dcm_service.hpp"
#include "../doip/doip_codec.hpp"
#include "../doip/socket_io.hpp"
#include "../uds/uds_utils.hpp"

#include <arpa/inet.h>
#include <cstring>
#include <iostream>
#include <sys/socket.h>
#include <unistd.h>

int main() {
    int serverFd = socket(AF_INET, SOCK_STREAM, 0);
    if (serverFd < 0) {
        std::cerr << "socket create failed\n";
        return 1;
    }

    int opt = 1;
    setsockopt(serverFd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(doip::kPort);
    addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(serverFd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
        std::cerr << "bind failed\n";
        return 1;
    }
    if (listen(serverFd, 1) < 0) {
        std::cerr << "listen failed\n";
        return 1;
    }

    std::cout << "DoIP server listening on 0.0.0.0:" << doip::kPort << "\n";

    sockaddr_in clientAddr{};
    socklen_t clientLen = sizeof(clientAddr);
    int clientFd = accept(serverFd, reinterpret_cast<sockaddr*>(&clientAddr), &clientLen);
    if (clientFd < 0) {
        std::cerr << "accept failed\n";
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

    std::vector<uint8_t> frame(8 + payloadLen);
    std::memcpy(frame.data(), header, 8);
    if (!doip::recvAll(clientFd, frame.data() + 8, payloadLen)) {
        std::cerr << "recv payload failed\n";
        return 1;
    }

    doip::DiagnosticMessage meta;
    uds::Message udsRequest;
    if (!doip::decodeDiagnosticFrame(frame, meta, udsRequest)) {
        std::cerr << "invalid doip frame\n";
        return 1;
    }

    std::cout << "Rx UDS from tester 0x" << std::hex << meta.sourceAddress
              << " to ecu 0x" << meta.targetAddress << ": "
              << uds::bytesToHex(udsRequest) << std::dec << "\n";

    dcm::DcmService dcm;
    const uds::Message udsResponse = dcm.handleRequest(udsRequest);
    std::vector<uint8_t> responseFrame = doip::encodeDiagnosticFrame(
        meta.targetAddress, meta.sourceAddress, udsResponse);

    if (!doip::sendAll(clientFd, responseFrame.data(), responseFrame.size())) {
        std::cerr << "send response failed\n";
        return 1;
    }

    std::cout << "Tx UDS response: " << uds::bytesToHex(udsResponse) << "\n";

    close(clientFd);
    close(serverFd);
    return 0;
}
