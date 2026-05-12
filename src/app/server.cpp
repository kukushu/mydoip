#include "../dcm/dcm_service.hpp"
#include "../doip/doip_codec.hpp"
#include "../doip/socket_io.hpp"
#include "../uds/uds_utils.hpp"

#include <arpa/inet.h>
#include <cstring>
#include <iostream>
#include <sys/socket.h>
#include <unistd.h>
#include <vector>

namespace {

bool handleOneClient(int clientFd, const dcm::DcmService& dcm) {
    uint8_t header[8];
    if (!doip::recvAll(clientFd, header, 8)) {
        return false;
    }

    uint32_t payloadLenN = 0;
    std::memcpy(&payloadLenN, &header[4], 4);
    const uint32_t payloadLen = ntohl(payloadLenN);

    std::vector<uint8_t> frame(8 + payloadLen);
    std::memcpy(frame.data(), header, 8);
    if (!doip::recvAll(clientFd, frame.data() + 8, payloadLen)) {
        return false;
    }

    doip::DiagnosticMessage meta;
    uds::Message udsRequest;
    if (!doip::decodeDiagnosticFrame(frame, meta, udsRequest)) {
        std::cerr << "invalid doip frame\n";
        return false;
    }

    std::cout << "Rx UDS from tester 0x" << std::hex << meta.sourceAddress
              << " to ecu 0x" << meta.targetAddress << ": "
              << uds::bytesToHex(udsRequest) << std::dec << "\n";

    const uds::Message udsResponse = dcm.handleRequest(udsRequest);
    std::vector<uint8_t> responseFrame =
        doip::encodeDiagnosticFrame(meta.targetAddress, meta.sourceAddress, udsResponse);

    if (!doip::sendAll(clientFd, responseFrame.data(), responseFrame.size())) {
        return false;
    }

    std::cout << "Tx UDS response: " << uds::bytesToHex(udsResponse) << "\n";
    return true;
}

}  // namespace

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
    if (listen(serverFd, 8) < 0) {
        std::cerr << "listen failed\n";
        return 1;
    }

    std::cout << "DoIP server listening on 0.0.0.0:" << doip::kPort
              << " (Ctrl+C to stop)\n";

    dcm::DcmService dcm;
    while (true) {
        sockaddr_in clientAddr{};
        socklen_t clientLen = sizeof(clientAddr);
        int clientFd = accept(serverFd, reinterpret_cast<sockaddr*>(&clientAddr), &clientLen);
        if (clientFd < 0) {
            std::cerr << "accept failed\n";
            continue;
        }

        char ip[INET_ADDRSTRLEN] = {0};
        inet_ntop(AF_INET, &clientAddr.sin_addr, ip, sizeof(ip));
        std::cout << "Client connected: " << ip << ":" << ntohs(clientAddr.sin_port) << "\n";

        while (handleOneClient(clientFd, dcm)) {
        }

        std::cout << "Client disconnected\n";
        close(clientFd);
    }

    close(serverFd);
    return 0;
}
