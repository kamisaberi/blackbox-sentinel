# Subsystem 21: Hardware Power & Emission Anomaly Analyzer (`21_side_channel`)

`21_side_channel` analyzes side-channel emissions—including hardware power consumption profiles, electrical supply ripple, and electromagnetic (EM) variations—ingested via analog-to-digital converters (ADCs) or hardware current shunts (e.g., INA219, INA3221). It detects hardware Trojan activations and unauthorized firmware tampering without interacting with the host OS.

---

## 1. Power Waveform FFT Pipeline

```text
 [ Hardware Current Shunt / ADC Input (e.g. 100 kHz Sampling) ]
                             │
                             ▼
 ┌─────────────────────────────────────────────────────────────┐
 │ Circular Waveform Ring Buffer (1024 Samples)                │
 └───────────────────────────┬─────────────────────────────────┘
                             │
                             ▼ Fast Fourier Transform (KissFFT / AVX2)
 ┌─────────────────────────────────────────────────────────────┐
 │ Frequency Spectrum Distribution:                            │
 │  • Baseline Steady State: Constant harmonic at 50/60 Hz     │
 │  • Trojan / Injection: High-frequency spectral spikes       │
 │    induced by unauthorized CPU micro-loops (10-25 kHz)      │
 └───────────────────────────┬─────────────────────────────────┘
                             │
                             ▼ Compute Spectral Distance
 [ Anomaly Detected: Power Signature Diverges -> Alert SIEM ]
```

---

## 2. Invariants & Speed

* **Hardware Independence:** Detects attacks even when host kernel logging, syslog, and network interfaces have been compromised or blinded by kernel rootkits.
* **FFT Evaluation Latency:** Evaluates a 1024-point real-to-complex FFT in **$< 45\,\mu\text{s}$**.

