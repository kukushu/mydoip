#include "dcm_service.hpp"

#include "../config/demo_config.hpp"

#include <string>

namespace dcm {

uds::Message DcmService::negativeResponse(uint8_t sid, uint8_t nrc) {
    return {uds::kSidNegativeResponse, sid, nrc};
}

DcmService::AccessRule DcmService::resolveServiceRule(uint8_t sid) const {
    switch (sid) {
        case uds::kSidReadDataByIdentifier:
            return {config::kRequiredSessionDefaultForDid, config::kRequireSecurityDefaultForDid};
        case uds::kSidRoutineControl:
            return {config::kRequiredSessionDefaultForRoutine, config::kRequireSecurityDefaultForRoutine};
        default:
            return {config::kRequiredSessionDefault, config::kRequireSecurityDefault};
    }
}

DcmService::AccessRule DcmService::resolveDidRule(uint16_t did) const {
    switch (did) {
        case config::kVinDid:
            return {config::kRequiredSessionForDidVin, config::kRequireSecurityForDidVin};
        default:
            return {config::kRequiredSessionDefaultForDid, config::kRequireSecurityDefaultForDid};
    }
}

DcmService::AccessRule DcmService::resolveRoutineRule(uint16_t routineId) const {
    switch (routineId) {
        case config::kSupportedRoutineId:
            return {config::kRequiredSessionForRoutineFF00, config::kRequireSecurityForRoutineFF00};
        default:
            return {config::kRequiredSessionDefaultForRoutine, config::kRequireSecurityDefaultForRoutine};
    }
}

bool DcmService::isRuleAllowed(const AccessRule& rule) const {
    if (rule.requiredSession != 0x00 && currentSession_ != rule.requiredSession) {
        return false;
    }
    if (rule.requireSecurity && !securityUnlocked_) {
        return false;
    }
    return true;
}

uds::Message DcmService::handleRequest(const uds::Message& request) {
    if (request.empty()) return negativeResponse(0x00, 0x13);

    const uint8_t sid = request[0];

    if (sid != uds::kSidDiagnosticSessionControl && sid != uds::kSidSecurityAccess) {
        if (!isRuleAllowed(resolveServiceRule(sid))) {
            return negativeResponse(sid, 0x33);
        }
    }

    switch (sid) {
        case uds::kSidDiagnosticSessionControl: {
            if (request.size() < 2) return negativeResponse(sid, 0x13);
            const uint8_t session = request[1];
            currentSession_ = session;
            securityUnlocked_ = false;
            return {static_cast<uint8_t>(sid + 0x40), session, 0x00, 0x32, 0x01, 0xF4};
        }
        case uds::kSidReadDataByIdentifier: {
            if (request.size() < 3) return negativeResponse(sid, 0x13);
            const uint16_t did = static_cast<uint16_t>(request[1] << 8 | request[2]);
            if (!isRuleAllowed(resolveDidRule(did))) {
                return negativeResponse(sid, 0x33);
            }
            if (did == config::kVinDid) {
                const std::string vin = "WVWZZZ1JZXW000001";
                uds::Message response{static_cast<uint8_t>(sid + 0x40), request[1], request[2]};
                response.insert(response.end(), vin.begin(), vin.end());
                return response;
            }
            return negativeResponse(sid, 0x31);
        }
        case uds::kSidSecurityAccess: {
            if (request.size() < 2) return negativeResponse(sid, 0x13);

            const uint8_t subFunction = request[1];
            if (subFunction == 0x01) {
                securityUnlocked_ = false;
                const uint8_t seedHi = static_cast<uint8_t>((config::kSecuritySeed >> 8) & 0xFF);
                const uint8_t seedLo = static_cast<uint8_t>(config::kSecuritySeed & 0xFF);
                return {static_cast<uint8_t>(sid + 0x40), subFunction, seedHi, seedLo};
            }

            if (subFunction == 0x02) {
                if (request.size() < 4) return negativeResponse(sid, 0x13);
                const uint16_t key = static_cast<uint16_t>(request[2] << 8 | request[3]);
                if (key != config::kSecurityExpectedKey) {
                    securityUnlocked_ = false;
                    return negativeResponse(sid, 0x35);
                }
                securityUnlocked_ = true;
                return {static_cast<uint8_t>(sid + 0x40), subFunction};
            }

            return negativeResponse(sid, 0x12);
        }
        case uds::kSidRoutineControl: {
            if (request.size() < 4) return negativeResponse(sid, 0x13);

            const uint8_t subFunction = request[1];
            const uint16_t routineId = static_cast<uint16_t>(request[2] << 8 | request[3]);
            if (!isRuleAllowed(resolveRoutineRule(routineId))) {
                return negativeResponse(sid, 0x33);
            }
            if (routineId != config::kSupportedRoutineId) {
                return negativeResponse(sid, 0x31);
            }

            if (subFunction != 0x01 && subFunction != 0x02 && subFunction != 0x03) {
                return negativeResponse(sid, 0x12);
            }

            uds::Message response{static_cast<uint8_t>(sid + 0x40), subFunction, request[2], request[3]};
            if (subFunction == 0x03) {
                response.push_back(0x00);
            }
            return response;
        }
        default:
            return negativeResponse(sid, 0x11);
    }
}

}  // namespace dcm
