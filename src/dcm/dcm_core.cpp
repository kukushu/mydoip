#include "dcm_core.hpp"

#include "../config/demo_config.hpp"
#include "../uds/protocol.hpp"
#include "../common/log/logger.hpp"

#include <filesystem>
#include <chrono>

namespace dcm {
namespace {
static uint64_t nowMs() {
    using namespace std::chrono;
    return duration_cast<milliseconds>(steady_clock::now().time_since_epoch()).count();
}

constexpr uint16_t kDidWritableExample = 0xF191;
constexpr uint16_t kSecuritySeedLevel1 = 0x1234;
constexpr uint16_t kSecuritySeedLevel2 = 0x5678;
constexpr uint16_t kSecurityKeyLevel1 = 0xB89E;
constexpr uint16_t kSecurityKeyLevel2 = 0x9ABC;
}

uds::Message DcmCore::negativeResponse(uint8_t sid, uint8_t nrc) { return {uds::kSidNegativeResponse, sid, nrc}; }

bool DcmCore::isRuleAllowed(const AccessRule& rule) const {
    if (rule.requiredSession != 0x00 && context_.currentSession != rule.requiredSession) return false;
    if (rule.requiredSecurityLevel != 0 && context_.currentSecurityLevel < rule.requiredSecurityLevel) return false;
    return true;
}

uds::Message DcmCore::handleSessionControl(const uds::Message& request) {
    if (request.size() < 2) return negativeResponse(uds::kSidDiagnosticSessionControl, uds::kNrcIncorrectMessageLengthOrInvalidFormat);
    context_.currentSession = request[1];
    LOG_INFO("DCM", "Session switched to 0x" + std::to_string(request[1]));
    context_.currentSecurityLevel = 0;
    return {0x50, request[1], 0x00, 0x32, 0x01, 0xF4};
}

uds::Message DcmCore::handleSecurityAccess(const uds::Message& request) {
    if (request.size() < 2) return negativeResponse(uds::kSidSecurityAccess, uds::kNrcIncorrectMessageLengthOrInvalidFormat);
    const uint8_t sub = request[1];
    if (sub == 0x01) return {0x67, sub, static_cast<uint8_t>(kSecuritySeedLevel1 >> 8), static_cast<uint8_t>(kSecuritySeedLevel1)};
    if (sub == 0x02) {
        if (request.size() < 4) return negativeResponse(uds::kSidSecurityAccess, uds::kNrcIncorrectMessageLengthOrInvalidFormat);
        const uint16_t key = static_cast<uint16_t>(request[2] << 8 | request[3]);
        if (key != kSecurityKeyLevel1) return negativeResponse(uds::kSidSecurityAccess, uds::kNrcInvalidKey);
        context_.currentSecurityLevel = 1;
        securityUnlockMs_ = nowMs();
        LOG_INFO("DCM", "Security level unlocked: 1");
        return {0x67, sub};
    }
    if (sub == 0x03) return {0x67, sub, static_cast<uint8_t>(kSecuritySeedLevel2 >> 8), static_cast<uint8_t>(kSecuritySeedLevel2)};
    if (sub == 0x04) {
        if (request.size() < 4) return negativeResponse(uds::kSidSecurityAccess, uds::kNrcIncorrectMessageLengthOrInvalidFormat);
        const uint16_t key = static_cast<uint16_t>(request[2] << 8 | request[3]);
        if (key != kSecurityKeyLevel2) return negativeResponse(uds::kSidSecurityAccess, uds::kNrcInvalidKey);
        context_.currentSecurityLevel = 2;
        securityUnlockMs_ = nowMs();
        LOG_INFO("DCM", "Security level unlocked: 2");
        return {0x67, sub};
    }
    return negativeResponse(uds::kSidSecurityAccess, uds::kNrcSubFunctionNotSupported);
}

uds::Message DcmCore::handleReadDid(const uds::Message& request) {
    if (request.size() < 3) return negativeResponse(uds::kSidReadDataByIdentifier, uds::kNrcIncorrectMessageLengthOrInvalidFormat);
    const uint16_t did = static_cast<uint16_t>(request[1] << 8 | request[2]);
    if (!isRuleAllowed(policy_.didRule(did, false))) return negativeResponse(uds::kSidReadDataByIdentifier, uds::kNrcSecurityAccessDenied);
    uds::Message resp{0x62, request[1], request[2]};
    if (did == config::kVinDid) {
        const char* vin = "WVWZZZ1JZXW000001";
        resp.insert(resp.end(), vin, vin + 17);
        return resp;
    }
    auto data = didStore_.read(did);
    if (!data.has_value()) return negativeResponse(uds::kSidReadDataByIdentifier, uds::kNrcRequestOutOfRange);
    resp.insert(resp.end(), data->begin(), data->end());
    return resp;
}

uds::Message DcmCore::handleWriteDid(const uds::Message& request) {
    if (request.size() < 4) return negativeResponse(uds::kSidWriteDataByIdentifier, uds::kNrcIncorrectMessageLengthOrInvalidFormat);
    const uint16_t did = static_cast<uint16_t>(request[1] << 8 | request[2]);
    if (!isRuleAllowed(policy_.didRule(did, true))) return negativeResponse(uds::kSidWriteDataByIdentifier, uds::kNrcSecurityAccessDenied);
    if (did != kDidWritableExample) return negativeResponse(uds::kSidWriteDataByIdentifier, uds::kNrcRequestOutOfRange);
    didStore_.write(did, std::vector<uint8_t>(request.begin() + 3, request.end()));
    return {0x6E, request[1], request[2]};
}

uds::Message DcmCore::handleRoutineControl(const uds::Message& request) {
    if (request.size() < 4) return negativeResponse(uds::kSidRoutineControl, uds::kNrcIncorrectMessageLengthOrInvalidFormat);
    const uint8_t sub = request[1];
    const uint16_t rid = static_cast<uint16_t>(request[2] << 8 | request[3]);
    if (!isRuleAllowed(policy_.routineRule(rid))) return negativeResponse(uds::kSidRoutineControl, uds::kNrcSecurityAccessDenied);
    if (rid != config::kSupportedRoutineId) return negativeResponse(uds::kSidRoutineControl, uds::kNrcRequestOutOfRange);
    if (sub != 0x01 && sub != 0x02 && sub != 0x03) return negativeResponse(uds::kSidRoutineControl, uds::kNrcSubFunctionNotSupported);
    uds::Message resp{0x71, sub, request[2], request[3]};
    if (sub == 0x03) resp.push_back(0x00);
    return resp;
}


uds::Message DcmCore::handleTransferData(const uds::Message& request) {
    if (!isRuleAllowed({0x03, 2})) return negativeResponse(uds::kSidTransferData, uds::kNrcSecurityAccessDenied);
    if (!transferActive_) return negativeResponse(uds::kSidTransferData, uds::kNrcRequestOutOfRange);
    if (request.size() < 2) return negativeResponse(uds::kSidTransferData, uds::kNrcIncorrectMessageLengthOrInvalidFormat);
    const uint8_t blockCounter = request[1];
    if (blockCounter != expectedBlockCounter_) return negativeResponse(uds::kSidTransferData, 0x73);

    if (fileReplaceMode_) {
        if (!transferFile_.is_open()) return negativeResponse(uds::kSidTransferData, uds::kNrcGeneralReject);
        transferFile_.write(reinterpret_cast<const char*>(request.data() + 2), static_cast<std::streamsize>(request.size() - 2));
        LOG_DEBUG("DCM", "Write transfer block=" + std::to_string(blockCounter) + " bytes=" + std::to_string(request.size() - 2));
        if (!transferFile_) return negativeResponse(uds::kSidTransferData, uds::kNrcGeneralReject);
    }

    expectedBlockCounter_++;
    return {0x76, blockCounter};
}

uds::Message DcmCore::handleRequestTransferExit(const uds::Message& request) {
    (void)request;
    if (!isRuleAllowed({0x03, 2})) return negativeResponse(uds::kSidRequestTransferExit, uds::kNrcSecurityAccessDenied);
    if (!transferActive_) return negativeResponse(uds::kSidRequestTransferExit, uds::kNrcRequestOutOfRange);

    if (fileReplaceMode_ && transferFile_.is_open()) {
        transferFile_.flush();
        transferFile_.close();
    }

    transferActive_ = false;
    expectedBlockCounter_ = 1;
    fileReplaceMode_ = false;
    return {0x77};
}

uds::Message DcmCore::handleRequestFileTransfer(const uds::Message& request) {
    if (!isRuleAllowed({0x03, 2})) return negativeResponse(uds::kSidRequestFileTransfer, uds::kNrcSecurityAccessDenied);
    if (request.size() < 3) return negativeResponse(uds::kSidRequestFileTransfer, uds::kNrcIncorrectMessageLengthOrInvalidFormat);
    const uint8_t modeOfOperation = request[1];

    transferActive_ = false;
    expectedBlockCounter_ = 1;
    fileReplaceMode_ = false;
    targetFilePath_.clear();
    if (transferFile_.is_open()) transferFile_.close();

    if (modeOfOperation == 0x03) {
        const uint8_t fileNameLen = request[2];
        if (request.size() < static_cast<size_t>(3 + fileNameLen) || fileNameLen == 0) {
            return negativeResponse(uds::kSidRequestFileTransfer, uds::kNrcIncorrectMessageLengthOrInvalidFormat);
        }
        std::string fileName(request.begin() + 3, request.begin() + 3 + fileNameLen);
        std::filesystem::create_directories("/tmp/doip_files");
        targetFilePath_ = std::string("/tmp/doip_files/") + fileName;

        transferFile_.open(targetFilePath_, std::ios::binary | std::ios::trunc);
        LOG_INFO("DCM", "Open transfer target: " + targetFilePath_);
        if (!transferFile_.is_open()) {
            return negativeResponse(uds::kSidRequestFileTransfer, uds::kNrcGeneralReject);
        }
        fileReplaceMode_ = true;
    }

    transferActive_ = true;
    transferStartMs_ = nowMs();
    return {0x78, modeOfOperation, 0x20, 0x00};
}

uds::Message DcmCore::process(const uds::Message& request) {
    if (request.empty()) return negativeResponse(0x00, uds::kNrcIncorrectMessageLengthOrInvalidFormat);
    lastActivityMs_ = nowMs();
    switch (request[0]) {
        case uds::kSidDiagnosticSessionControl: return handleSessionControl(request);
        case uds::kSidSecurityAccess: return handleSecurityAccess(request);
        case uds::kSidReadDataByIdentifier: return handleReadDid(request);
        case uds::kSidWriteDataByIdentifier: return handleWriteDid(request);
        case uds::kSidRoutineControl: return handleRoutineControl(request);
        case uds::kSidTransferData: return handleTransferData(request);
        case uds::kSidRequestTransferExit: return handleRequestTransferExit(request);
        case uds::kSidRequestFileTransfer: return handleRequestFileTransfer(request);
        default: return negativeResponse(request[0], uds::kNrcServiceNotSupported);
    }
}



void DcmCore::tick(uint64_t now) {
    if (context_.currentSecurityLevel > 0 && securityUnlockMs_ > 0 &&
        now > securityUnlockMs_ + static_cast<uint64_t>(config::kDcmSecurityTimeoutMs)) {
        LOG_WARN("DCM", "Security level timeout, reset to 0");
        context_.currentSecurityLevel = 0;
        securityUnlockMs_ = 0;
    }
    if (transferActive_ && transferStartMs_ > 0 &&
        now > transferStartMs_ + static_cast<uint64_t>(config::kDcmTransferTimeoutMs)) {
        LOG_WARN("DCM", "Transfer timeout, aborting transfer");
        if (transferFile_.is_open()) transferFile_.close();
        transferActive_ = false;
        fileReplaceMode_ = false;
        expectedBlockCounter_ = 1;
        transferStartMs_ = 0;
    }
}

}  // namespace dcm
