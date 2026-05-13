#pragma once

#include <cstdint>
#include <optional>
#include <vector>

namespace dcm {

class IDidStore {
public:
    virtual ~IDidStore() = default;
    virtual std::optional<std::vector<uint8_t>> read(uint16_t did) const = 0;
    virtual void write(uint16_t did, const std::vector<uint8_t>& data) = 0;
};

}  // namespace dcm
