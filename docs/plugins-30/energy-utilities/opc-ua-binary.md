---

### File: `blackbox-sentinel/docs/plugins-30/energy-utilities/opc-ua-binary.md`

```markdown
# OPC UA Binary Protocol Dissector (`libsentinel_plugin_opcua.so`)

The OPC UA (Open Platform Communications Unified Architecture) dissector inspects Industry 4.0 machine-to-machine communications on TCP port **4840**. It validates TCP transport framing (`HEL`, `ACK`, `OPN`, `MSG`), SecureChannel asymmetric handshakes, and node management services.

---

## 1. Transport Layer Deconstruction

```text
 ┌─────────────────────────────────────────────────────────────┐
 │ OPC UA TCP Message Header (8 Bytes)                         │
 │  [ MessageType: 3B ('HEL', 'ACK', 'OPN', 'MSG', 'CLO') ]    │
 │  [ ChunkType  : 1B ('F' = Final, 'C' = Intermediate) ]      │
 │  [ MessageSize: 4B (Total frame byte count) ]               │
 └──────────────────────────────┬──────────────────────────────┘
                                │
                                ▼ MessageType == 'MSG'
 ┌─────────────────────────────────────────────────────────────┐
 │ SecureChannel & Security Header                             │
 │  [ SecureChannelId: 4B ] [ SecurityTokenId: 4B ]            │
 │  [ SecurityPolicyURI: Length + String ]                     │
 └──────────────────────────────┬──────────────────────────────┘
                                │
        ┌───────────────────────┴───────────────────────┐
        ▼ Insecure Configuration                        ▼ Secure Handshake
 ┌─────────────────────────────┐         ┌─────────────────────────────┐
 │ Policy: "http://opcfound... │         │ Policy: "Basic256Sha256"    │
 │ .../SecurityPolicy#None"    │         │ Policy: "Aes128_Sha256_Rsa" │
 └──────────────┬──────────────┘         └─────────────────────────────┘
                │
                ▼ INSECURE CONNECTION TRAPPED
 [ Downgrade Attack Identified -> Enforces Kernel Drop / Reset ]
```

---

## 2. Trapping Cryptographic Downgrade Attacks

Industrial adversaries force OPC UA servers into insecure states by requesting `SecurityPolicy#None`. 
`libsentinel_plugin_opcua.so` intercepts OpenSecureChannel (`OPN`) requests, dropping sessions that attempt unencrypted communication in protected production zones.
```

