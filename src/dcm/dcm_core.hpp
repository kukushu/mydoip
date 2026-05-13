#pragma once

#include "access_policy.hpp"
#include "dcm_context.hpp"
#include "store/ram_did_store.hpp"

#include <fstream>
#include <string>
#include "../uds/uds_types.hpp"

namespace dcm {

class DcmCore {
public:
    uds::Message process(const uds::Message& request);

private:
    static uds::Message negativeResponse(uint8_t sid, uint8_t nrc);
    bool isRuleAllowed(const AccessRule& rule) const;

    uds::Message handleSessionControl(const uds::Message& request);
    uds::Message handleSecurityAccess(const uds::Message& request);
    uds::Message handleReadDid(const uds::Message& request);
    uds::Message handleWriteDid(const uds::Message& request);
    uds::Message handleRoutineControl(const uds::Message& request);
    uds::Message handleTransferData(const uds::Message& request);
    uds::Message handleRequestTransferExit(const uds::Message& request);
    uds::Message handleRequestFileTransfer(const uds::Message& request);

    DcmContext context_{};
    AccessPolicy policy_{};
    RamDidStore didStore_{};
    bool transferActive_{false};
    uint8_t expectedBlockCounter_{1};
    bool fileReplaceMode_{false};
    std::string targetFilePath_{};
    std::ofstream transferFile_{};
};

}  // namespace dcm
