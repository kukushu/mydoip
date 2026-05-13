#pragma once

#include "dcm_core.hpp"

namespace dcm {

class DcmService {
public:
    uds::Message handleRequest(const uds::Message& request);
    void tick(uint64_t nowMs);

private:
    DcmCore core_{};
};

}  // namespace dcm
