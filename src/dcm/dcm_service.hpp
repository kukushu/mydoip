#pragma once

#include "dcm_core.hpp"

namespace dcm {

class DcmService {
public:
    uds::Message handleRequest(const uds::Message& request);

private:
    DcmCore core_{};
};

}  // namespace dcm
