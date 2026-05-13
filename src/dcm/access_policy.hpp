#pragma once

#include <cstdint>

namespace dcm {

struct AccessRule {
    uint8_t requiredSession;
    uint8_t requiredSecurityLevel;
};

class AccessPolicy {
public:
    AccessRule didRule(uint16_t did, bool forWrite) const;
    AccessRule routineRule(uint16_t rid) const;
};

}  // namespace dcm
