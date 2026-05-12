#pragma once

#include "../uds/uds_types.hpp"

#include <cstdint>

namespace dcm {

class DcmService {
public:
    uds::Message handleRequest(const uds::Message& request);

private:
    struct AccessRule {
        uint8_t requiredSession;
        bool requireSecurity;
    };

    static uds::Message negativeResponse(uint8_t sid, uint8_t nrc);
    AccessRule resolveServiceRule(uint8_t sid) const;
    AccessRule resolveDidRule(uint16_t did) const;
    AccessRule resolveRoutineRule(uint16_t routineId) const;
    bool isRuleAllowed(const AccessRule& rule) const;

    uint8_t currentSession_{0x01};
    bool securityUnlocked_{false};
};

}  // namespace dcm
