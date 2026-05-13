#include "../config/demo_config.hpp"
#include "../doip/doip_frame.hpp"
#include "../doip/socket_io.hpp"
#include "../uds/uds_utils.hpp"

#include <arpa/inet.h>
#include <cstring>
#include <iostream>
#include <string>
#include <sys/socket.h>
#include <unistd.h>
#include <vector>

namespace {

bool sendDoipFrame(int fd, uint16_t payloadType, const std::vector<uint8_t>& payload) {
    doip::Frame frame{};
    frame.header.payloadType = payloadType;
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
    const uint32_t len = ntohl(lenN);
    std::vector<uint8_t> raw(8 + len);
    std::memcpy(raw.data(), header, 8);
    if (!doip::recvAll(fd, raw.data() + 8, len)) return false;
    return doip::decodeFrame(raw, frame);
}

bool sendUdsAndExpect(int fd, const std::vector<uint8_t>& udsReq, const std::vector<uint8_t>& expectedPrefix,
                      const std::string& caseName) {
    std::vector<uint8_t> payload;
    payload.push_back(static_cast<uint8_t>((config::kTesterAddress >> 8) & 0xFF));
    payload.push_back(static_cast<uint8_t>(config::kTesterAddress & 0xFF));
    payload.push_back(static_cast<uint8_t>((config::kEcuAddress >> 8) & 0xFF));
    payload.push_back(static_cast<uint8_t>(config::kEcuAddress & 0xFF));
    payload.insert(payload.end(), udsReq.begin(), udsReq.end());

    if (!sendDoipFrame(fd, static_cast<uint16_t>(doip::PayloadType::DiagnosticMessage), payload)) {
        std::cerr << "[FAIL] " << caseName << ": send failed\n";
        return false;
    }

    doip::Frame resp;
    if (!recvDoipFrame(fd, resp)) {
        std::cerr << "[FAIL] " << caseName << ": recv failed\n";
        return false;
    }
    if (resp.header.payloadType != static_cast<uint16_t>(doip::PayloadType::DiagnosticMessage) || resp.payload.size() < 4) {
        std::cerr << "[FAIL] " << caseName << ": invalid doip resp\n";
        return false;
    }

    std::vector<uint8_t> udsResp(resp.payload.begin() + 4, resp.payload.end());
    if (udsResp.size() < expectedPrefix.size()) {
        std::cerr << "[FAIL] " << caseName << ": resp too short: " << uds::bytesToHex(udsResp) << "\n";
        return false;
    }
    for (size_t i = 0; i < expectedPrefix.size(); ++i) {
        if (udsResp[i] != expectedPrefix[i]) {
            std::cerr << "[FAIL] " << caseName << ": got " << uds::bytesToHex(udsResp)
                      << " expected prefix " << uds::bytesToHex(expectedPrefix) << "\n";
            return false;
        }
    }
    std::cout << "[PASS] " << caseName << " => " << uds::bytesToHex(udsResp) << "\n";
    return true;
}

}  // namespace

int main() {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return 1;

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
    if (!recvDoipFrame(fd, raResp) || raResp.payload.size() < 5 || raResp.payload[4] != 0x10) {
        std::cerr << "RA failed\n";
        return 2;
    }

    bool ok = true;
    ok &= sendUdsAndExpect(fd, {0x10, 0x03}, {0x50, 0x03}, "session 10 03");
    ok &= sendUdsAndExpect(fd, {0x22, 0xF1, 0x90}, {0x7F, 0x22, 0x33}, "read vin before unlock denied");
    ok &= sendUdsAndExpect(fd, {0x27, 0x01}, {0x67, 0x01}, "security seed l1");
    ok &= sendUdsAndExpect(fd, {0x27, 0x02, 0xB8, 0x9E}, {0x67, 0x02}, "security key l1");
    ok &= sendUdsAndExpect(fd, {0x22, 0xF1, 0x90}, {0x62, 0xF1, 0x90}, "read vin after l1");
    ok &= sendUdsAndExpect(fd, {0x2E, 0xF1, 0x91, 0x12, 0x34}, {0x7F, 0x2E, 0x33}, "write did before l2 denied");
    ok &= sendUdsAndExpect(fd, {0x27, 0x03}, {0x67, 0x03}, "security seed l2");
    ok &= sendUdsAndExpect(fd, {0x27, 0x04, 0x9A, 0xBC}, {0x67, 0x04}, "security key l2");
    ok &= sendUdsAndExpect(fd, {0x2E, 0xF1, 0x91, 0xDE, 0xAD}, {0x6E, 0xF1, 0x91}, "write did after l2");
    ok &= sendUdsAndExpect(fd, {0x22, 0xF1, 0x91}, {0x62, 0xF1, 0x91, 0xDE, 0xAD}, "read did written value");
    ok &= sendUdsAndExpect(fd, {0x31, 0x01, 0xFF, 0x00}, {0x71, 0x01, 0xFF, 0x00}, "routine control start");

    close(fd);
    if (!ok) return 3;
    std::cout << "All test cases passed.\n";
    return 0;
}
