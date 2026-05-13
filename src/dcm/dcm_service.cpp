#include "dcm_service.hpp"

namespace dcm {

uds::Message DcmService::handleRequest(const uds::Message& request) { return core_.process(request); }

void DcmService::tick(uint64_t nowMs) { core_.tick(nowMs); }

}  // namespace dcm
