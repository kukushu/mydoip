#pragma once

#include <cstdint>
#include <vector>

namespace uds {

constexpr uint8_t kSidNegativeResponse = 0x7F;
constexpr uint8_t kSidDiagnosticSessionControl = 0x10;
constexpr uint8_t kSidReadDataByIdentifier = 0x22;

using Message = std::vector<uint8_t>;

}  // namespace uds
