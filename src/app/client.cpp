#include "../config/demo_config.hpp"
#include "../doip/doip_frame.hpp"
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
        if (ss.fail() || !ss.eof() || value > 0xFF) return false;
        out.push_back(static_cast<uint8_t>(value));
    }
    return !out.empty();
}

bool sendDoipFrame(int fd, uint16_t pt, const std::vector<uint8_t>& payload) {
    doip::Frame frame{};
    frame.header.payloadType = pt;
    frame.payload = payload;
    std::vector<uint8_t> raw;
    doip::encodeFrame(frame, raw);
    return doip::sendAll(fd, raw.data(), raw.size());
}

bool recvDoipFrame(int fd, doip::Frame& frame) {
    uint8_t header[8];
    if (!doip::recvAll(fd, header, 8)) return false;
    uint32_t lenN = 0;
    std::memcpy(&lenN, &header[4], 4);
    uint32_t len = ntohl(lenN);
    std::vector<uint8_t> raw(8 + len);
    std::memcpy(raw.data(), header, 8);
    if (!doip::recvAll(fd, raw.data() + 8, len)) return false;
    return doip::decodeFrame(raw, frame);
}
}  // namespace

int main() {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(config::kDoipPort);
    inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
    if (connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) return 1;

    std::vector<uint8_t> raReq(7, 0x00);
    raReq[0] = static_cast<uint8_t>((config::kTesterAddress >> 8) & 0xFF);
    raReq[1] = static_cast<uint8_t>(config::kTesterAddress & 0xFF);
    raReq[2] = 0x00;
    if (!sendDoipFrame(fd, static_cast<uint16_t>(doip::PayloadType::RoutingActivationRequest), raReq)) return 1;
    doip::Frame raResp;
    if (!recvDoipFrame(fd, raResp)) return 1;

    std::cout << "RA response code: 0x" << std::hex << static_cast<int>(raResp.payload.size() > 4 ? raResp.payload[4] : 0xFF)
              << std::dec << "\n";

    std::string line;
    while (true) {
        std::cout << "> ";
        if (!std::getline(std::cin, line) || line == "q") break;
        uds::Message req;
        if (!parseHexUdsLine(line, req)) continue;
        std::vector<uint8_t> payload;
        payload.push_back(static_cast<uint8_t>((config::kTesterAddress >> 8) & 0xFF));
        payload.push_back(static_cast<uint8_t>(config::kTesterAddress & 0xFF));
        payload.push_back(static_cast<uint8_t>((config::kEcuAddress >> 8) & 0xFF));
        payload.push_back(static_cast<uint8_t>(config::kEcuAddress & 0xFF));
        payload.insert(payload.end(), req.begin(), req.end());
        sendDoipFrame(fd, static_cast<uint16_t>(doip::PayloadType::DiagnosticMessage), payload);
        doip::Frame resp;
        if (!recvDoipFrame(fd, resp)) break;
        if (resp.header.payloadType != static_cast<uint16_t>(doip::PayloadType::DiagnosticMessage)) continue;
        std::vector<uint8_t> udsResp(resp.payload.begin() + 4, resp.payload.end());
        std::cout << uds::bytesToHex(udsResp) << "\n";
    }
    close(fd);
    return 0;
}
