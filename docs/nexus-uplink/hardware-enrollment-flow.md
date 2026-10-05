---

### File: `blackbox-sentinel/docs/nexus-uplink/hardware-enrollment-flow.md`

```markdown
# Hardware Identity Enrollment & Handshake Flow

When an edge appliance connects to `sentinel-nexus`, it undergoes a cryptographic enrollment handshake rooted in its physical TPM 2.0 silicon.

---

## 1. Handshake Protocol Sequence

```text
Edge Appliance (NexusUplink)                         Fleet Command (Nexus Hub)
       │                                                         │
       │ 1. InitiateEnrollmentRequest(appliance_uuid)            │
       ├────────────────────────────────────────────────────────►│
       │                                                         │
       │ 2. InitiateEnrollmentResponse(challenge_nonce_32b)      │
       │◄────────────────────────────────────────────────────────┤
       │                                                         │
 ┌─────┴────────────────────────────────┐                        │
 │ - Invokes HardwareIdentity::instance()│                        │
 │ - Generates TPM Quote over PCR 0 & 4 │                        │
 │ - Hardware signs nonce using AIK     │                        │
 └─────┬────────────────────────────────┘                        │
       │                                                         │
       │ 3. CompleteEnrollmentRequest(TPM_Quote + Public AIK)    │
       ├────────────────────────────────────────────────────────►│
       │                                                         │
       │                                            ┌────────────┴────────────┐
       │                                            │ Validates:              │
       │                                            │ • TPM Quote signature   │
       │                                            │ • Golden PCR 0 baseline │
       │                                            │ • Nonce match           │
       │                                            └────────────┬────────────┘
       │                                                         │
       │ 4. EnrollmentSuccess(ApplianceJWTToken, Lease=24h)      │
       │◄────────────────────────────────────────────────────────┤
```

---

## 2. Protobuf Specification (`sentinel_nexus.proto`)

```protobuf
syntax = "proto3";
package sentinel.nexus;

service FleetOrchestrator {
    rpc InitiateEnrollment(EnrollmentInitRequest) returns (EnrollmentInitResponse);
    rpc CompleteEnrollment(EnrollmentCompleteRequest) returns (EnrollmentCompleteResponse);
}

message EnrollmentInitRequest {
    string appliance_uuid = 1;
    string hostname = 2;
    string agent_version = 3;
}

message EnrollmentInitResponse {
    bytes challenge_nonce = 1; // 32 bytes cryptographically secure random token
    int64 expiry_timestamp_ns = 2;
}

message EnrollmentCompleteRequest {
    string appliance_uuid = 1;
    bytes tpm_quote_signature = 2;
    bytes pcr_digest = 3;
    bytes aik_public_cert = 4;
    uint32 pcr_mask = 5;
}

message EnrollmentCompleteResponse {
    bool enrolled = 1;
    string auth_token = 2; // Signed Bearer JWT for gRPC metadata
    int64 lease_duration_sec = 3;
}
```

---

## 3. Threat Mitigation

* **Rogue Node Rejection:** Appliances running modified bootloaders or unauthorized UEFI firmware fail PCR 0 validation and are rejected.
* **Clone Detection:** Snapshot clones of virtual appliances fail challenge nonces due to non-monotonic hardware counter states.
```

