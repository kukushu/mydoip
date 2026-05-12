#pragma once

#include "../uds/uds_types.hpp"

#include <cstdint>
#include <unordered_map>
#include <vector>

namespace dcm {

class DcmService {
public:
    uds::Message handleRequest(const uds::Message& request);

private:
    struct AccessRule {
        uint8_t requiredSession;
        uint8_t requiredSecurityLevel;  // 0 means no security required
    };

    static uds::Message negativeResponse(uint8_t sid, uint8_t nrc);
    AccessRule resolveDidRule(uint16_t did, bool forWrite) const;
    AccessRule resolveRoutineRule(uint16_t rid) const;
    bool isRuleAllowed(const AccessRule& rule) const;

    uds::Message handleSessionControl(const uds::Message& request);
    uds::Message handleSecurityAccess(const uds::Message& request);
    uds::Message handleReadDid(const uds::Message& request);
    uds::Message handleWriteDid(const uds::Message& request);
    uds::Message handleRoutineControl(const uds::Message& request);

    uint8_t currentSession_{0x01};
    uint8_t currentSecurityLevel_{0};
    std::unordered_map<uint16_t, std::vector<uint8_t>> didStore_;
};

}  // namespace dcm
