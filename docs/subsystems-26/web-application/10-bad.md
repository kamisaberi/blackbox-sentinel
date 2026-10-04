---

### File: `blackbox-sentinel/docs/subsystems-26/web-application/10-bad.md`

```markdown
# Subsystem 10: Bot & Automated Abuse Defense (`10_bad`)

`10_bad` detects automated scrapers, credential-stuffing bots, and DDoS flooding scripts by analyzing the **kinematic curves** of client interactions and the statistical periodicity of incoming HTTP requests.

---

## 1. Kinematic Curve Analysis

Human interactions (mouse movements, touch swipes) exhibit continuous acceleration, deceleration, and natural jitter governed by physical biomechanics. Bots generate linear vectors, programmatic Bezier curves, or instantaneous point jumps:

```text
 HUMAN MOUSE VELOCITY PROFILE:
 Velocity
   ▲         .-.
   │        /   \     (Continuous acceleration/deceleration curves)
   │   .---'     `--.
   └───┴──────────────┴────► Time

 AUTOMATED BOT MOVEMENT PROFILE:
 Velocity
   ▲   ┌─────────┐
   │   │         │    (Instantaneous acceleration; static intervals)
   └───┴─────────┴─────────► Time
```

---

## 2. Request Periodicity FFT

`10_bad` computes a Fast Fourier Transform (FFT) over the inter-arrival times of incoming requests per IP. Automated loops display sharp spectral peaks at fixed intervals (e.g., exactly every $100\,\text{ms}$), triggering automated mitigation.
```

