# DNP3 Electric Substation Dissector (`libsentinel_plugin_dnp3.so`)

The DNP3 (Distributed Network Protocol) dissector inspects electric utility telecontrol and SCADA traffic on TCP/UDP port **20000**. It parses Data Link, Transport, and Application layers to detect unauthorized **Select-Before-Operate (SBO)** relay tripping, class poll anomalies, and outstation address spoofing.

---

## 1. Protocol Layer Deconstruction

```text
 ┌─────────────────────────────────────────────────────────────┐
 │ Data Link Layer: [ Start 0x0564: 2B ] [ Len: 1B ] [ Ctrl: 1B]│
 │                  [ Destination: 2B ] [ Source: 2B ] [ CRC: 2B]│
 └──────────────────────────────┬──────────────────────────────┘
                                │
                                ▼
 ┌─────────────────────────────────────────────────────────────┐
 │ Application Layer: [ App Control: 1B ] [ Function Code: 1B ]│
 └──────────────────────────────┬──────────────────────────────┘
                                │
        ┌───────────────────────┼───────────────────────┐
        ▼ Polling Operations    ▼ Direct Operate        ▼ Select-Before-Operate
 ┌──────────────┐        ┌──────────────┐        ┌──────────────┐
 │ FC 01: Read  │        │ FC 05: Direct│        │ FC 03: Select│
 │ Classes 0/1/2│        │ Operate (Risk│        │ FC 04: Operate│
 │ (Telemetry)  │        │ High)        │        │ (Substation) │
 └──────────────┘        └──────┬───────┘        └──────┬───────┘
                                │                       │
                                └───────────┬───────────┘
                                            │ Check Outstation Whitelist
                                            ▼
               [ Detects Unauthorized Breaker Opening Commands ]
```

---

## 2. Invariant Enforcement & Threat Signatures

* **Direct Operate Suppression:** Industrial electrical safety standards mandate the use of `Select-Before-Operate` (FC `03` followed by FC `04`) before tripping high-voltage switchgear. Issuing unexpected `Direct Operate No Ack` (FC `06`) commands indicates automated grid sabotages (e.g., **Industroyer2**) and triggers an immediate in-kernel block.
* **CRC Validation:** Evaluates the DNP3 Data Link CRC-16 polynomial ($X^{16} + X^{13} + X^8 + 1$) in hardware via AVX2 instructions.

