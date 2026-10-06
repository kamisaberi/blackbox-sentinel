# Real-Time Explainable AI (XAI) Feature Attribution Viewer

Traditional Deep Learning models operate as opaque "black boxes," making it difficult for plant operators to understand why a model triggered an automated in-kernel drop.

`blackbox-sentinel` incorporates **Microsecond Residual Decomposition (MRD)**, rendering the **top-3 physical feature deviations** live on the web console within milliseconds of an attack mitigation.

---

## 1. Microsecond Residual Decomposition (MRD) Architecture

Instead of calculating computationally prohibitive SHAP or LIME values (which take seconds to evaluate), the C++ engine computes element-wise autoencoder residuals in **$< 80\,\text{nanoseconds}$**:

$$e_j = (x_j - \hat{x}_j)^2$$

$$\text{Top-3 Attributions} = \operatorname{arg\,max}_{j \in \{1 \dots D\}} \left(e_j\right)$$

```text
 [ Model Prediction Anomaly Flagged (Reconstruction MSE > 0.082) ]
                               │
                               ▼ Fast Element-wise Residual Compute (< 80 ns)
 ┌─────────────────────────────────────────────────────────────┐
 │ Semantic Dictionary Attribution Lookup (SemanticDictionary.hpp)
 ├─────────────────────────────────────────────────────────────┤
 │ #1 Contributor (64%): Modbus Target Register 40001 Overwrite│
 │ #2 Contributor (24%): Flow Packet Rate Deviation (+75k pps) │
 │ #3 Contributor (12%): Abnormal TCP Window Zero-Flagging     │
 └─────────────────────────────┬───────────────────────────────┘
                               │ Streamed to Web Console
                               ▼
 ┌─────────────────────────────────────────────────────────────┐
 │ Web UI XAI Proof Card: Explains root cause to operator      │
 └─────────────────────────────────────────────────────────────┘
```

---

## 2. Web UI XAI Proof Display

```text
 ┌─────────────────────────────────────────────────────────────────────────────┐
 │ THREAT EXPLAINABILITY AUDIT: Incident #1802 (Modbus Anomaly)                │
 ├─────────────────────────────────────────────────────────────────────────────┤
 │ Anomaly Score: 0.284 (Threshold: 0.082) | Mitigation: In-Kernel XDP_DROP    │
 │ Target IP    : 198.51.100.42            | Reaction Time : 0.82 µs           │
 ├─────────────────────────────────────────────────────────────────────────────┤
 │ TOP 3 PHYSICAL FEATURE DEVIATIONS:                                          │
 │                                                                             │
 │ [1] Modbus Register Setpoint (40001)                                        │
 │     Observed: 9,850 PSI | Baseline Normal: 2,100 PSI (Residual: +7,750 PSI) │
 │     Deviation Bar: ████████████████████████████████ 64%                     │
 │                                                                             │
 │ [2] Packet Ingress Rate                                                     │
 │     Observed: 82,000 pps | Baseline Normal: 150 pps                         │
 │     Deviation Bar: ████████████ 24%                                         │
 │                                                                             │
 │ [3] Inter-Arrival Time Variance                                             │
 │     Observed: 0.001 ms | Baseline Normal: 12.5 ms                           │
 │     Deviation Bar: ██████ 12%                                               │
 └─────────────────────────────────────────────────────────────────────────────┘
```

---

## 3. Operational Benefits

* **Root Cause Clarity:** Field engineers immediately see which register, sensor, or network parameter triggered the mitigation.
* **Audit Admissibility:** Proves to industrial regulators that automated drops were governed by physical process boundaries rather than arbitrary heuristic errors.

