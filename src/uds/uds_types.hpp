#pragma once

#include <cstdint>
#include <vector>

namespace uds {

constexpr uint8_t kSidNegativeResponse = 0x7F;
constexpr uint8_t kSidDiagnosticSessionControl = 0x10;
constexpr uint8_t kSidReadDataByIdentifier = 0x22;
constexpr uint8_t kSidWriteDataByIdentifier = 0x2E;
constexpr uint8_t kSidSecurityAccess = 0x27;
constexpr uint8_t kSidRoutineControl = 0x31;
constexpr uint8_t kSidTransferData = 0x36;
constexpr uint8_t kSidRequestTransferExit = 0x37;
constexpr uint8_t kSidRequestFileTransfer = 0x38;

using Message = std::vector<uint8_t>;

}  // namespace uds
