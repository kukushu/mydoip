#include "../config/demo_config.hpp"
#include "../doip/doip_codec.hpp"
#include "../doip/socket_io.hpp"
#include "../uds/uds_types.hpp"
#include "../uds/uds_utils.hpp"

#include <arpa/inet.h>
#include <cstring>
#include <iostream>
#include <sstream>
#include <string>
#include <sys/socket.h>
#include <unistd.h>
#include <vector>

namespace {

bool parseHexUdsLine(const std::string& line, uds::Message& out) {
    out.clear();
    std::istringstream iss(line);
    std::string token;
    while (iss >> token) {
        unsigned int value = 0;
        std::stringstream ss;
        ss << std::hex << token;
        ss >> value;
        if (ss.fail() || !ss.eof() || value > 0xFF) {
            return false;
        }
        out.push_back(static_cast<uint8_t>(value));
    }
    return !out.empty();
}

}  // namespace

int main() {
    int clientFd = socket(AF_INET, SOCK_STREAM, 0);
    if (clientFd < 0) {
        std::cerr << "socket create failed\n";
        return 1;
    }

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(config::kDoipPort);
    inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);

    if (connect(clientFd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
        std::cerr << "connect failed\n";
        return 1;
    }

    std::cout << "Connected to DoIP server on 127.0.0.1:" << config::kDoipPort << "\n";
    std::cout << "Input UDS hex bytes (example: 22 F1 90), type q to quit.\n";

    std::string line;
    while (true) {
        std::cout << "> ";
        if (!std::getline(std::cin, line)) break;
        if (line == "q" || line == "quit" || line == "exit") break;

        uds::Message udsRequest;
        if (!parseHexUdsLine(line, udsRequest)) {
            std::cout << "Invalid input. Use hex bytes separated by spaces, e.g. 10 03\n";
            continue;
        }

        std::vector<uint8_t> requestFrame =
            doip::encodeDiagnosticFrame(config::kTesterAddress, config::kEcuAddress, udsRequest);

        std::cout << "Tx UDS request: " << uds::bytesToHex(udsRequest) << "\n";
        if (!doip::sendAll(clientFd, requestFrame.data(), requestFrame.size())) {
            std::cerr << "send request failed\n";
            break;
        }

        uint8_t header[8];
        if (!doip::recvAll(clientFd, header, 8)) {
            std::cerr << "recv header failed\n";
            break;
        }

        uint32_t payloadLenN = 0;
        std::memcpy(&payloadLenN, &header[4], 4);
        const uint32_t payloadLen = ntohl(payloadLenN);

        std::vector<uint8_t> responseFrame(8 + payloadLen);
        std::memcpy(responseFrame.data(), header, 8);
        if (!doip::recvAll(clientFd, responseFrame.data() + 8, payloadLen)) {
            std::cerr << "recv payload failed\n";
            break;
        }

        doip::DiagnosticMessage meta;
        uds::Message udsResponse;
        if (!doip::decodeDiagnosticFrame(responseFrame, meta, udsResponse)) {
            std::cerr << "invalid doip frame\n";
            break;
        }

        std::cout << "Rx UDS response from ecu 0x" << std::hex << meta.sourceAddress
                  << ": " << uds::bytesToHex(udsResponse) << std::dec << "\n";
    }

    close(clientFd);
    return 0;
}
