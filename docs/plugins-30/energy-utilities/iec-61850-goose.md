# IEC 61850 GOOSE Substation Multicast Dissector (`libsentinel_plugin_goose.so`)

The IEC 61850 GOOSE (Generic Object Oriented Substation Events) dissector analyzes high-speed Layer 2 protection relay multicasts operating over **EtherType `0x88B8`**. It inspects State Numbers (`stNum`), Sequence Numbers (`sqNum`), and Dataset contents to prevent unauthorized protective relay tripping and replay-induced regional blackouts.

---

## 1. GOOSE Layer 2 Frame Architecture

GOOSE runs directly over Ethernet multicast without IP or TCP/UDP headers to achieve trip propagation latencies of under $4\,\text{milliseconds}$:

```text
 ┌─────────────────────────────────────────────────────────────┐
 │ Ethernet Header: [ Multicast Dest: 01:0C:CD:01:00:xx ]      │
 │                  [ EtherType: 0x88B8 ]                      │
 └──────────────────────────────┬──────────────────────────────┘
                                │
                                ▼
 ┌─────────────────────────────────────────────────────────────┐
 │ GOOSE APDU Header                                           │
 │  [ APPID: 2B ] [ Length: 2B ] [ Reserved: 4B ]              │
 └──────────────────────────────┬──────────────────────────────┘
                                │
                                ▼ ASN.1 BER Encoded Payload
 ┌─────────────────────────────────────────────────────────────┐
 │ GOOSE PDU Structure:                                        │
 │  • gocbRef   : Control Block Reference (e.g., "Relay1/LLN0$GO$gcb01")
 │  • timeAllowedtoLive : Retransmission decay window          │
 │  • stNum     : Monotonic State Counter                      │
 │  • sqNum     : Heartbeat Sequence Counter                   │
 │  • allData   : Protection status bit array                  │
 └──────────────────────────────┬──────────────────────────────┘
                                │
                                ▼ Anomaly Validation
 ┌─────────────────────────────────────────────────────────────┐
 │ Traps:                                                      │
 │  • stNum Regression or Out-of-Order Replay Attacks          │
 │  • Unannounced Trip State Shift from Non-Authorized MAC     │
 └─────────────────────────────────────────────────────────────┘
```

---

## 2. Detecting GOOSE Replay & Injection Attacks

`libsentinel_plugin_goose.so` enforces monotonic sequence invariants per `gocbRef`:
1. **Replay Rejection:** If an incoming GOOSE frame has an `stNum` less than or equal to the current state counter for that control block with an identical timestamp, it is flagged as a replayed injection attack.
2. **MAC Verification:** Trip messages must match the pre-enrolled physical switchgear MAC address; spoofed source MACs are dropped at wire speed.

