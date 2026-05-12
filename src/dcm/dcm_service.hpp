#pragma once

#include "../uds/uds_types.hpp"

namespace dcm {

class DcmService {
public:
    uds::Message handleRequest(const uds::Message& request) const;

private:
    static uds::Message negativeResponse(uint8_t sid, uint8_t nrc);
};

}  // namespace dcm
