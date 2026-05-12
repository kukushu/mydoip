#include "dcm_service.hpp"

#include <string>

namespace dcm {

uds::Message DcmService::negativeResponse(uint8_t sid, uint8_t nrc) {
    return {uds::kSidNegativeResponse, sid, nrc};
}

uds::Message DcmService::handleRequest(const uds::Message& request) const {
    if (request.empty()) return negativeResponse(0x00, 0x13);

    const uint8_t sid = request[0];
    switch (sid) {
        case uds::kSidDiagnosticSessionControl: {
            if (request.size() < 2) return negativeResponse(sid, 0x13);
            const uint8_t session = request[1];
            return {static_cast<uint8_t>(sid + 0x40), session, 0x00, 0x32, 0x01, 0xF4};
        }
        case uds::kSidReadDataByIdentifier: {
            if (request.size() < 3) return negativeResponse(sid, 0x13);
            const uint16_t did = static_cast<uint16_t>(request[1] << 8 | request[2]);
            if (did == 0xF190) {
                const std::string vin = "WVWZZZ1JZXW000001";
                uds::Message response{static_cast<uint8_t>(sid + 0x40), request[1], request[2]};
                response.insert(response.end(), vin.begin(), vin.end());
                return response;
            }
            return negativeResponse(sid, 0x31);
        }
        default:
            return negativeResponse(sid, 0x11);
    }
}

}  // namespace dcm
