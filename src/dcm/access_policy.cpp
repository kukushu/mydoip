#include "access_policy.hpp"

#include "../config/demo_config.hpp"

namespace dcm {
namespace {
constexpr uint16_t kDidWritableExample = 0xF191;
}

AccessRule AccessPolicy::didRule(uint16_t did, bool forWrite) const {
    if (did == config::kVinDid) {
        return {0x03, static_cast<uint8_t>(forWrite ? 0 : 1)};
    }
    if (did == kDidWritableExample) {
        return {0x03, 2};
    }
    return {0x03, static_cast<uint8_t>(forWrite ? 2 : 1)};
}

AccessRule AccessPolicy::routineRule(uint16_t) const { return {0x03, 2}; }

}  // namespace dcm
