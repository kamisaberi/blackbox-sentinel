---

### File: `blackbox-sentinel/docs/nexus-uplink/ota-model-updates.md`

```markdown
# Over-the-Air (OTA) Model Updates & Zero-Downtime Hot Reloads

`blackbox-sentinel` supports remote neural network weight updates staged by the `xinfer-forge` training pipeline and distributed by `sentinel-nexus`.

---

## 1. Staged OTA Rollout Stages

```text
 Sentinel-Nexus Model Repository (app.aryorithm.com)
                        │
                        ▼ Staged Canary Deployment
 ┌─────────────────────────────────────────────────────────────┐
 │ STAGE 1: SHADOW EVALUATION                                  │
 │   - Download candidate model (network_threat_v2.onnx)       │
 │   - Evaluate predictions in parallel with production model  │
 │   - Zero active kernel drop authority                       │
 └──────────────────────┬──────────────────────────────────────┘
                        │ Pass Criteria: Accuracy >= 99.8%
                        ▼
 ┌─────────────────────────────────────────────────────────────┐
 │ STAGE 2: CANARY FLEET ENFORCEMENT                           │
 │   - 5% of fleet appliances activated in live mitigation     │
 │   - Monitored by RollbackGuard (> 1000µs SLA breaches abort)│
 └──────────────────────┬──────────────────────────────────────┘
                        │ Pass Criteria: Zero False Positive Drops
                        ▼
 ┌─────────────────────────────────────────────────────────────┐
 │ STAGE 3: FLEET-WIDE PROMOTION                               │
 │   - Complete rollout across all edge nodes                  │
 └─────────────────────────────────────────────────────────────┘
```

---

## 2. In-Process Model Hot Reload API

When a validated model payload finishes downloading:
1. `NexusUplink` verifies its SHA-256 hash against the manifest.
2. It sends an internal command to the embedded web server:
   ```bash
   POST /api/v1/control/reload-model
   ```
3. The inference engine (`xinfer::InferenceEngine`) instantiates a new execution plan for the candidate model in secondary memory, performs an atomic pointer swap, and releases the old model weights—achieving **zero-downtime weight updates**.
```

