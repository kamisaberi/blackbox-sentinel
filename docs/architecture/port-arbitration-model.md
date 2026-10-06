# Port Arbitration: Promiscuous Raw Sockets vs. Secondary VIPs

Deploying an active security daemon on an industrial network creates an operational challenge: how does the appliance monitor, inspect, and defend critical ports (such as Modbus on port `502` or S7Comm on port `102`) without conflicting with legitimate PLC control software running on the same host?

`blackbox-sentinel` resolves this using **Dual-Mode Port Arbitration**.

---

## 1. The Conflict Dilemma

```text
 ┌─────────────────────────────────────────────────────────────┐
 │ CONFLICT SCENARIO:                                          │
 │ Legitimate Local SCADA Server binds to 0.0.0.0:502          │
 │ Deception Decoy / Honey-PLC attempts to bind to 0.0.0.0:502 │
 │ RESULT: Bind failure -> Address already in use (EADDRINUSE) │
 └─────────────────────────────────────────────────────────────┘
```

---

## 2. The Solution: Dual-Mode Port Arbitration

```text
 ┌─────────────────────────────────────────────────────────────────────────────┐
 │                       PHYSICAL INTERFACE: eth0                              │
 │            Primary IP: 10.240.0.100 (Host & Legitimate Services)            │
 └──────────────────────┬──────────────────────────────┬───────────────────────┘
                        │                              │
         MODE 1: PASSIVE SNIFFING                      │ MODE 2: DECEPTION VIPs
         Promiscuous AF_XDP / Raw Sockets              │ Secondary Virtual IP:
         (Zero Socket Binding)                         │ eth0:1 = 10.240.0.199
                        │                              │
                        ▼                              ▼
         ┌─────────────────────────────┐        ┌─────────────────────────────┐
         │ Passive Inspection Engine   │        │ 26_ddp (Decoy Honey-PLC)    │
         │ - Sniffs traffic invisibly  │        │ - Explicitly binds to       │
         │ - Zero port collisions      │        │   10.240.0.199:502 via      │
         │ - Subsystems 01-25 Active   │        │   SO_BINDTODEVICE           │
         └─────────────────────────────┘        └─────────────────────────────┘
```

---

## 3. Secondary VIP Binding Logic

When the deception subsystem (`26_ddp`) launches decoy Modbus or Siemens PLCs:
1. It registers an isolated virtual IP alias (e.g., `ip addr add 10.240.0.199/24 dev eth0 label eth0:1`).
2. Decoy listeners bind exclusively to the virtual IP (`10.240.0.199`) using `SO_BINDTODEVICE`, leaving `10.240.0.100` and `0.0.0.0` unencumbered.
3. Legitimate plant PLCs continue normal operations while adversaries scanning the subnet interact with the isolated honeypot environment.

