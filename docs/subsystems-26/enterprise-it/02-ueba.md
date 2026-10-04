---

### File: `blackbox-sentinel/docs/subsystems-26/enterprise-it/02-ueba.md`

```markdown
# Subsystem 02: User & Entity Behavior Analytics (`02_ueba`)

`02_ueba` models baseline operational profiles for up to **100,000 network entities** (users, IP addresses, service accounts, and PLC nodes). It detects credential stuffing, insider threats, privilege escalation, and beaconing behavior by computing deviations from rolling statistical baselines.

---

## 1. The 100,000-Entity State Matrix

To prevent dynamic heap allocation, `02_ueba` uses a statically pre-allocated state matrix:

```text
 ┌─────────────────────────────────────────────────────────────┐
 │ 100k-Entity State Matrix (Fixed 256 MB Static Allocation)   │
 └──────────────────────────────┬──────────────────────────────┘
                                │ Hash(Entity ID) & (131072 - 1)
                                ▼
 ┌─────────────────────────────────────────────────────────────┐
 │ EntitySlot [131,072 Buckets]                                │
 │  - Baseline Moving Average (Packets, Bytes, Flow Durations) │
 │  - First-Order Markov Chain (State Transition Matrix)       │
 │  - Activity Time Histogram (24-Hour Binned Array)           │
 │  - Cumulative Risk Score (0.0 to 100.0)                     │
 └─────────────────────────────────────────────────────────────┘
```

---

## 2. Statistical Baseline & Markov Transition Model

The subsystem calculates anomaly probabilities using a combined metric score:

$$\text{Risk}(E) = w_1 \cdot \frac{|X_{\text{observed}} - \mu_{\text{baseline}}|}{\sigma_{\text{baseline}}} + w_2 \cdot \left(1.0 - P_{\text{Markov}}(S_t \mid S_{t-1})\right)$$

Where:
* $\frac{|X - \mu|}{\sigma}$ represents the Z-score deviation of connection frequencies or byte volumes.
* $P_{\text{Markov}}(S_t \mid S_{t-1})$ measures the probability of moving from protocol state $S_{t-1}$ (e.g., SMB Read) to state $S_t$ (e.g., Active Directory DCSync) based on historical entity habits.

---

## 3. Configuration Parameters (`sentinel.yaml`)

```yaml
subsystems:
  ueba:
    enabled: true
    max_tracked_entities: 100000
    learning_window_hours: 168 # 7 Days baseline
    risk_threshold_alert: 75.0
    risk_threshold_mitigate: 90.0 # Triggers in-kernel drop
```
```

