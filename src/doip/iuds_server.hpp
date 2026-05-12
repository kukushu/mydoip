#pragma once

#include <cstdint>
#include <vector>

namespace doip {

class IUdsServer {
public:
    virtual ~IUdsServer() = default;
    virtual std::vector<uint8_t> processUdsRequest(uint16_t sourceAddress, uint16_t targetAddress,
                                                   const std::vector<uint8_t>& request) = 0;
};

}  // namespace doip
