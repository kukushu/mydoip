#pragma once

#include "access_policy.hpp"
#include "dcm_context.hpp"
#include "store/ram_did_store.hpp"
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

    DcmContext context_{};
    AccessPolicy policy_{};
    RamDidStore didStore_{};
};

}  // namespace dcm
