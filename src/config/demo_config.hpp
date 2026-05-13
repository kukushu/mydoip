#pragma once

#include <cstdint>

namespace config {

// DoIP transport
constexpr uint16_t kDoipPort = 13400;
constexpr uint8_t kDoipProtocolVersion = 0x02;
constexpr uint16_t kDoipPayloadTypeDiagnosticMessage = 0x8001;

// Logical addresses used by demo apps
constexpr uint16_t kTesterAddress = 0x0E00;
constexpr uint16_t kEcuAddress = 0x1001;

// Demo DCM identifiers
constexpr uint16_t kVinDid = 0xF190;
constexpr uint16_t kSupportedRoutineId = 0xFF00;

// Demo SecurityAccess data
constexpr uint16_t kSecuritySeed = 0x1234;
constexpr uint16_t kSecurityExpectedKey = 0xB89E;

// Service-level access control policy (fallback)
constexpr uint8_t kRequiredSessionDefault = 0x03;  // ExtendedSession
constexpr bool kRequireSecurityDefault = true;

// DID-level access control policy
constexpr uint8_t kRequiredSessionDefaultForDid = 0x03;
constexpr bool kRequireSecurityDefaultForDid = true;

constexpr uint8_t kRequiredSessionForDidVin = 0x03;
constexpr bool kRequireSecurityForDidVin = true;

// RID-level access control policy
constexpr uint8_t kRequiredSessionDefaultForRoutine = 0x03;
constexpr bool kRequireSecurityDefaultForRoutine = true;

constexpr uint8_t kRequiredSessionForRoutineFF00 = 0x03;
constexpr bool kRequireSecurityForRoutineFF00 = true;

// Timeout settings
constexpr int kDoipPollMs = 200;
constexpr int kDoipRxInactivityTimeoutMs = 5000;
constexpr int kDoipAliveCheckResponseTimeoutMs = 1500;
constexpr int kDcmSecurityTimeoutMs = 10000;
constexpr int kDcmTransferTimeoutMs = 15000;

}  // namespace config
