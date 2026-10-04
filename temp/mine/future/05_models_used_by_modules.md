Here is the master architectural mapping of the **exact ONNX model names, neural network architectures, input/output tensor specifications, and threat detection responsibilities** for all 26 modules of Blackbox Sentinel.

Every model file is stored under `models/` and loaded dynamically through `blackbox-essential` and `libxinfer.so` using your generic `ModelConfig` bindings.

---

### Master ONNX Models Specification (All 26 Modules)

| # | Module Name | Standard ONNX File Name | Neural Architecture | Input Tensor (Name, Shape, Type) | Output Tensor (Name, Shape, Type) | Target Threat Detection Task |
| :-: | :--- | :--- | :--- | :--- | :--- | :--- |
| **01** | `01_siem_core` | `siem_timeseries_lstm.onnx` | Temporal LSTM / GRU | `input`: `[1, 60, 8]` (FP32) | `scores`: `[1, 1]` (FP32) | Event frequency spike forecasting & multi-log anomaly correlation. |
| **02** | `02_ueba` | `ueba_dense_autoencoder.onnx` | Deep Autoencoder | `input`: `[1, 16]` (FP32) | `scores`: `[1, 1]` (FP32) | User baseline drift, abnormal session hours, and bulk data exfiltration. |
| **03** | `03_ndr` | `network_threat.onnx` | Temporal 1D-ResNet / Flow-CNN | `input`: `[1, 32]` (FP32) | `scores`: `[1, 2]` (FP32) | Encrypted Traffic Analysis (ETA), C2 beaconing, and TLS handshake anomalies. |
| **04** | `04_ids_ips` | `ids_payload_classifier.onnx` | 1D-CNN + Global Pooling | `input`: `[1, 128]` (FP32) | `scores`: `[1, 2]` (FP32) | Zero-day exploit shellcode patterns, buffer overflow payloads, and packet fuzzing. |
| **05** | `05_waf` | `waf_payload_char_cnn.onnx` | Character-Level CNN | `input`: `[1, 256]` (FP32) | `scores`: `[1, 4]` (FP32) | SQL Injection (SQLi), Cross-Site Scripting (XSS), RCE, and BOLA/IDOR API abuse. |
| **06** | `06_edr` | `edr_process_tree_mlp.onnx` | Lineage Graph MLP | `input`: `[1, 24]` (FP32) | `scores`: `[1, 1]` (FP32) | Illegitimate child process spawning (e.g. `nginx` $\rightarrow$ `sh`), reflective DLL injection. |
| **07** | `07_epp_ngav` | `epp_pe_malconv.onnx` | MalConv (Binary 1D-CNN) | `input`: `[1, 512]` (FP32) | `scores`: `[1, 2]` (FP32) | Pre-execution PE/ELF binary classification and high-entropy ransomware I/O blocks. |
| **08** | `08_nac` | `nac_device_classifier.onnx` | Multi-Class MLP / Softmax | `input`: `[1, 16]` (FP32) | `scores`: `[1, 7]` (FP32) | Device fingerprinting from DHCP/TCP options to isolate rogue network hardware. |
| **09** | `09_cwpp` | `cwpp_syscall_lstm.onnx` | Sequence LSTM | `input`: `[1, 32]` (INT64) | `scores`: `[1, 1]` (FP32) | Container breakout sequences (`setns`, `unshare`, `ptrace`) at kernel `sys_enter`. |
| **10** | `10_bad` | `bad_kinematics_mlp.onnx` | Kinematic Motion MLP | `input`: `[1, 20]` (FP32) | `scores`: `[1, 2]` (FP32) | Programmatic vs. human mouse trajectory curvature and automated credential stuffing. |
| **11** | `11_rasp` | `rasp_hook_detector.onnx` | Bytecode Classifier | `input`: `[1, 32]` (FP32) | `scores`: `[1, 1]` (FP32) | In-memory function prologue detours (0xE9 JMP patches) and SQL parameterization flaws. |
| **12** | `12_itdr` | `itdr_kerberos_gnn.onnx` | Graph Neural Network (GNN)| `input`: `[1, 18]` (FP32) | `scores`: `[1, 1]` (FP32) | Kerberoasting, golden/silver tickets, and Active Directory privilege escalation. |
| **13** | `13_ddos` | `ddos_rate_classifier.onnx` | Quantized INT8 MLP | `input`: `[1, 12]` (FP32) | `scores`: `[1, 1]` (FP32) | Hardware line-rate volumetric SYN floods, UDP amplification, and NTP reflections. |
| **14** | `14_ato` | `ato_velocity_detector.onnx`| Multi-Feature Autoencoder| `input`: `[1, 14]` (FP32) | `scores`: `[1, 1]` (FP32) | Impossible travel geo-velocity, device switching, and distributed credential stuffing. |
| **15** | `15_ngfw` | `ngfw_dpi_resnet1d.onnx` | 1D-ResNet Protocol Net | `input`: `[1, 64]` (FP32) | `scores`: `[1, 12]` (FP32)| Deep Packet Inspection (DPI) protocol classification (Tor, BitTorrent, WireGuard). |
| **16** | `16_cdr` | `cdr_document_scanner.onnx` | Byte Stream Classifier | `input`: `[1, 128]` (FP32) | `scores`: `[1, 1]` (FP32) | Embedded weaponized macros, `/Launch` actions, and DDE formulas in PDF/DOCX. |
| **17** | `17_iot_sec` | `iomt_protocol_guard.onnx` | Sequence Autoencoder | `input`: `[1, 24]` (FP32) | `scores`: `[1, 1]` (FP32) | DICOM PACS imaging buffer overflows and HL7 physiological vital-sign spoofing. |
| **18** | `18_cps_sec` | `cps_scada_physics.onnx` | Physics-Constrained LSTM | `input`: `[1, 16]` (FP32) | `scores`: `[1, 1]` (FP32) | Modbus/DNP3 commands commanding actuator states that violate physical laws (pressure/RPM).|
| **19** | `19_swg` | `swg_phishing_url_cnn.onnx` | Character-Level CNN | `input`: `[1, 128]` (INT64) | `scores`: `[1, 2]` (FP32) | Zero-minute phishing domains, typosquatting targets, and direct IP egress URLs. |
| **20** | `20_fse` | `fse_firmware_backdoor.onnx`| Binary Structure CNN | `input`: `[1, 256]` (FP32) | `scores`: `[1, 1]` (FP32) | Disassembled UEFI/BIOS firmware images containing MoonBounce/BlackLotus implants. |
| **21** | `21_side_channel`| `side_channel_dpa_cnn.onnx`| High-Frequency 1D-CNN | `input`: `[1, 256]` (FP32) | `scores`: `[1, 1]` (FP32) | Differential Power Analysis (DPA) and Simple Electro-Magnetic Analysis (SEMA) leaks. |
| **22** | `22_dfir` | `dfir_timeline_cluster.onnx`| Autoencoder Embedding Net | `input`: `[1, 48]` (FP32) | `scores`: `[1, 8]` (FP32) | Automated timeline event clustering from volatile RAM dumps and rolling PCAPs. |
| **23** | `23_ai_trism` | `ai_trism_prompt_guard.onnx`| MiniLM / DistilBERT | `input_ids`: `[1, 64]`, `attention_mask`: `[1, 64]` (INT64) | `scores`: `[1, 3]` (FP32) | LLM prompt injection (DAN mode), system prompt overrides, and PII/API key leaks. |
| **24** | `24_ztna` | `ztna_trust_regressor.onnx` | Continuous Regressor MLP | `input`: `[1, 20]` (FP32) | `scores`: `[1, 1]` (FP32) | Dynamic device trust score calculation $\in [0, 100]$ to adjust micro-segmentation. |
| **25** | `25_fdp` | `fdp_transaction_gnn.onnx` | Graph Neural Network (GNN)| `input`: `[1, 16]` (FP32) | `scores`: `[1, 1]` (FP32) | Circular money muling rings, velocity bursts, and synthetic account profiles. |
| **26** | `26_ddp` | `ddp_attacker_intent.onnx` | Sequence Intent Classifier | `input`: `[1, 12]` (FP32) | `scores`: `[1, 4]` (FP32) | Predicts attacker intent (Recon, Lateral, Exfil, Destruction) from honeypot interactions. |

---

### Mapping Models in `configs/modules/*.json`

Each module config dynamically binds its respective model and tensor names so the C++ engine remains unchanged. 

#### Example 1: `configs/modules/waf.json`
```json
{
  "module": "05_waf",
  "enabled": true,
  "model_path": "models/waf_payload_char_cnn.onnx",
  "input_tensor_name": "input",
  "output_tensor_name": "scores",
  "threshold": 0.85
}
```

#### Example 2: `configs/modules/ai_trism.json`
```json
{
  "module": "23_ai_trism",
  "enabled": true,
  "model_path": "models/ai_trism_prompt_guard.onnx",
  "input_tensor_name": "input_ids",
  "output_tensor_name": "scores",
  "threshold": 0.90
}
```

#### Example 3: `configs/modules/cps_sec.json`
```json
{
  "module": "18_cps_sec",
  "enabled": true,
  "model_path": "models/cps_scada_physics.onnx",
  "input_tensor_name": "input",
  "output_tensor_name": "scores",
  "threshold": 0.95
}
```

---

### How These Models are Hosted and Managed

1. **Lightweight Models ($<10\,\text{MB}$):** Modules 01 through 15, 17, 18, 21, and 24 through 26 use compact MLPs, Autoencoders, and 1D-CNNs. They are generated via PyTorch scripts in `xinfer-forge` and compile to under 50\,KB to 5\,MB each.
2. **Medium Models ($10\,\text{MB} - 50\,\text{MB}$):** Modules 16 (`cdr`), 19 (`swg`), 20 (`fse`), and 22 (`dfir`) use deeper 1D-ResNets and character CNNs.
3. **Transformer Models ($50\,\text{MB} - 400\,\text{MB}$):** Module 23 (`ai_trism_prompt_guard.onnx`) uses a quantized MiniLM or DistilBERT backbone downloaded via `xinfer::ModelHub`.

Every single model in this table is fully compatible with **OpenVINO (CPU/NPU)**, **TensorRT (GPU)**, and **Rockchip (RKNN)**, executing within the microsecond latency budget of Sentinel.