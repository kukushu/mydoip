#include "dcm_service.hpp"

#include "../config/demo_config.hpp"

namespace dcm {
namespace {
constexpr uint8_t kNrcInvalidFormat = 0x13;
constexpr uint8_t kNrcSubFunctionNotSupported = 0x12;
constexpr uint8_t kNrcRequestOutOfRange = 0x31;
constexpr uint8_t kNrcSecurityDenied = 0x33;
constexpr uint8_t kNrcInvalidKey = 0x35;

constexpr uint16_t kDidWritableExample = 0xF191;
constexpr uint16_t kSecuritySeedLevel1 = 0x1234;
constexpr uint16_t kSecuritySeedLevel2 = 0x5678;
constexpr uint16_t kSecurityKeyLevel1 = 0xB89E;
constexpr uint16_t kSecurityKeyLevel2 = 0x9ABC;
}

uds::Message DcmService::negativeResponse(uint8_t sid, uint8_t nrc) {
    return {uds::kSidNegativeResponse, sid, nrc};
}

DcmService::AccessRule DcmService::resolveDidRule(uint16_t did, bool forWrite) const {
    if (did == config::kVinDid) {
        return {0x03, forWrite ? static_cast<uint8_t>(0) : static_cast<uint8_t>(1)};
    }
    if (did == kDidWritableExample) {
        return {0x03, 2};
    }
    return {0x03, forWrite ? static_cast<uint8_t>(2) : static_cast<uint8_t>(1)};
}

DcmService::AccessRule DcmService::resolveRoutineRule(uint16_t rid) const {
    if (rid == config::kSupportedRoutineId) return {0x03, 2};
    return {0x03, 2};
}

bool DcmService::isRuleAllowed(const AccessRule& rule) const {
    if (rule.requiredSession != 0x00 && currentSession_ != rule.requiredSession) return false;
    if (rule.requiredSecurityLevel != 0 && currentSecurityLevel_ < rule.requiredSecurityLevel) return false;
    return true;
}

uds::Message DcmService::handleSessionControl(const uds::Message& request) {
    if (request.size() < 2) return negativeResponse(uds::kSidDiagnosticSessionControl, kNrcInvalidFormat);
    currentSession_ = request[1];
    currentSecurityLevel_ = 0;  // session switch always clears security
    return {0x50, request[1], 0x00, 0x32, 0x01, 0xF4};
}

uds::Message DcmService::handleSecurityAccess(const uds::Message& request) {
    if (request.size() < 2) return negativeResponse(uds::kSidSecurityAccess, kNrcInvalidFormat);
    const uint8_t sub = request[1];
    if (sub == 0x01) {
        currentSecurityLevel_ = 0;
        return {0x67, sub, static_cast<uint8_t>(kSecuritySeedLevel1 >> 8), static_cast<uint8_t>(kSecuritySeedLevel1)};
    }
    if (sub == 0x02) {
        if (request.size() < 4) return negativeResponse(uds::kSidSecurityAccess, kNrcInvalidFormat);
        const uint16_t key = static_cast<uint16_t>(request[2] << 8 | request[3]);
        if (key != kSecurityKeyLevel1) return negativeResponse(uds::kSidSecurityAccess, kNrcInvalidKey);
        currentSecurityLevel_ = 1;
        return {0x67, sub};
    }
    if (sub == 0x03) {
        currentSecurityLevel_ = 0;
        return {0x67, sub, static_cast<uint8_t>(kSecuritySeedLevel2 >> 8), static_cast<uint8_t>(kSecuritySeedLevel2)};
    }
    if (sub == 0x04) {
        if (request.size() < 4) return negativeResponse(uds::kSidSecurityAccess, kNrcInvalidFormat);
        const uint16_t key = static_cast<uint16_t>(request[2] << 8 | request[3]);
        if (key != kSecurityKeyLevel2) return negativeResponse(uds::kSidSecurityAccess, kNrcInvalidKey);
        currentSecurityLevel_ = 2;
        return {0x67, sub};
    }
    return negativeResponse(uds::kSidSecurityAccess, kNrcSubFunctionNotSupported);
}

uds::Message DcmService::handleReadDid(const uds::Message& request) {
    if (request.size() < 3) return negativeResponse(uds::kSidReadDataByIdentifier, kNrcInvalidFormat);
    const uint16_t did = static_cast<uint16_t>(request[1] << 8 | request[2]);
    if (!isRuleAllowed(resolveDidRule(did, false))) return negativeResponse(uds::kSidReadDataByIdentifier, kNrcSecurityDenied);

    uds::Message resp{0x62, request[1], request[2]};
    if (did == config::kVinDid) {
        const char* vin = "WVWZZZ1JZXW000001";
        resp.insert(resp.end(), vin, vin + 17);
        return resp;
    }
    auto it = didStore_.find(did);
    if (it == didStore_.end()) return negativeResponse(uds::kSidReadDataByIdentifier, kNrcRequestOutOfRange);
    resp.insert(resp.end(), it->second.begin(), it->second.end());
    return resp;
}

uds::Message DcmService::handleWriteDid(const uds::Message& request) {
    if (request.size() < 4) return negativeResponse(uds::kSidWriteDataByIdentifier, kNrcInvalidFormat);
    const uint16_t did = static_cast<uint16_t>(request[1] << 8 | request[2]);
    if (!isRuleAllowed(resolveDidRule(did, true))) return negativeResponse(uds::kSidWriteDataByIdentifier, kNrcSecurityDenied);
    if (did != kDidWritableExample) return negativeResponse(uds::kSidWriteDataByIdentifier, kNrcRequestOutOfRange);

    didStore_[did] = std::vector<uint8_t>(request.begin() + 3, request.end());  // non-persistent RAM only
    return {0x6E, request[1], request[2]};
}

uds::Message DcmService::handleRoutineControl(const uds::Message& request) {
    if (request.size() < 4) return negativeResponse(uds::kSidRoutineControl, kNrcInvalidFormat);
    const uint8_t sub = request[1];
    const uint16_t rid = static_cast<uint16_t>(request[2] << 8 | request[3]);
    if (!isRuleAllowed(resolveRoutineRule(rid))) return negativeResponse(uds::kSidRoutineControl, kNrcSecurityDenied);
    if (rid != config::kSupportedRoutineId) return negativeResponse(uds::kSidRoutineControl, kNrcRequestOutOfRange);
    if (sub != 0x01 && sub != 0x02 && sub != 0x03) return negativeResponse(uds::kSidRoutineControl, kNrcSubFunctionNotSupported);
    uds::Message resp{0x71, sub, request[2], request[3]};
    if (sub == 0x03) resp.push_back(0x00);
    return resp;
}

uds::Message DcmService::handleRequest(const uds::Message& request) {
    if (request.empty()) return negativeResponse(0x00, kNrcInvalidFormat);
    switch (request[0]) {
        case uds::kSidDiagnosticSessionControl:
            return handleSessionControl(request);
        case uds::kSidSecurityAccess:
            return handleSecurityAccess(request);
        case uds::kSidReadDataByIdentifier:
            return handleReadDid(request);
        case uds::kSidWriteDataByIdentifier:
            return handleWriteDid(request);
        case uds::kSidRoutineControl:
            return handleRoutineControl(request);
        default:
            return negativeResponse(request[0], 0x11);
    }
}

}  // namespace dcm
