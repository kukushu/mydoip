#include "dcm_service.hpp"

namespace dcm {

uds::Message DcmService::handleRequest(const uds::Message& request) { return core_.process(request); }

}  // namespace dcm
