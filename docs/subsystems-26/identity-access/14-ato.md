# Subsystem 14: Account Takeover & Geo-Velocity Protection (`14_ato`)

`14_ato` detects compromised user credentials by calculating the physical **geo-velocity** between successive logins across distributed industrial and web endpoints.

---

## 1. The Impossible Travel Geo-Velocity Equation

When an account authenticates from Location $A$ at time $t_1$, and subsequently from Location $B$ at time $t_2$, `14_ato` calculates the minimum travel velocity using the Haversine great-circle distance formula:

$$d = 2R \cdot \arcsin\left(\sqrt{\sin^2\left(\frac{\Delta \phi}{2}\right) + \cos(\phi_1)\cos(\phi_2)\sin^2\left(\frac{\Delta \lambda}{2}\right)}\right)$$

$$\text{Velocity} = \frac{d(A, B)}{t_2 - t_1}$$

```text
 12:00:00 UTC: Login from Berlin, Germany (52.5200° N, 13.4050° E)
 12:15:00 UTC: Login from Tokyo, Japan   (35.6762° N, 139.6503° E)
 Distance    : 8,918 km
 Elapsed Time: 15 Minutes (0.25 Hours)
 Calculated Velocity: 35,672 km/h  ──► IMPOSSIBLE TRAVEL CONFIRMED!
```

---

## 2. Action Trigger

If calculated velocity exceeds $900\,\text{km/h}$ (commercial jet speed), `14_ato`:
1. Terminates the active session token immediately.
2. Injects the attacker's source IP into Tier 2 `blocked_ip_map`.
3. Issues a high-severity alert to `01_siem_core`.

