#pragma once

#include <cstdint>

namespace dcm {

struct DcmContext {
    uint8_t currentSession{0x01};
    uint8_t currentSecurityLevel{0};
};

}  // namespace dcm
