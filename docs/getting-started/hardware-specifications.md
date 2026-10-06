# Hardware Sizing & Appliance Specifications

`blackbox-sentinel` is available across three reference deployment form factors:

---

## 1. Model S-1000: Industrial DIN-Rail Edge Gateway

Designed for electrical substations, oil/gas wellheads, water treatment facilities, and rail transport cabinets.

```text
 ┌─────────────────────────────────────────────────────────────┐
 │ Model S-1000 Industrial DIN-Rail (Fanless Aluminum Chassis) │
 │  - Dimensions: 150mm x 100mm x 55mm                         │
 │  - Operating Temperature: -40°C to +75°C (Fanless)          │
 │  - Power Supply: Dual Redundant 12V-36V DC Terminal Block   │
 └─────────────────────────────────────────────────────────────┘
```

* **Processor:** Intel Core Ultra 7 165H (16 Cores, integrated NPU) or Rockchip RK3588 (8 Cores, 6 TOPS NPU).
* **Memory:** 16 GB DDR5 / LPDDR5 ECC RAM (Non-swappable).
* **Storage:** 128 GB Industrial Wide-Temp NVMe SSD (Encrypted with TPM 2.0).
* **Network Interfaces:** 4x 1GbE RJ45 (Intel i226-IT), bypass relay supported.
* **Hardware Identity:** Discrete Infineon OPTIGA TPM 2.0 (`/dev/tpmrm0`).
* **Throughput Capacity:** Up to $250{,}000\text{ EPS}$ sustained; $< 0.84\,\mu\text{s}$ mitigation.

---

## 2. Model S-5000: Enterprise 1U Rackmount Appliance

Designed for enterprise datacenters, hospital core switches, and municipal utility operations centers.

```text
 ┌─────────────────────────────────────────────────────────────┐
 │ Model S-5000 Enterprise 1U Rackmount Server                 │
 │  - Dual Redundant 750W Titanium Power Supplies              │
 │  - Hot-swappable enterprise cooling fan array               │
 └─────────────────────────────────────────────────────────────┘
```

* **Processor:** Dual Intel Xeon Platinum 8480+ (112 Cores total) or AMD EPYC 9654.
* **AI Acceleration:** Dedicated NVIDIA RTX A4000 (16 GB VRAM) or Intel Data Center GPU Flex 140.
* **Memory:** 128 GB DDR5-4800 Registered ECC RAM.
* **Storage:** 2x 1.92 TB Enterprise U.2 NVMe SSDs in RAID 1.
* **Network Interfaces:** 4x 10GbE/25GbE SFP28 (Intel E810-XXVDA2) with native AF_XDP driver support.
* **Hardware Identity:** Discrete STMicroelectronics ST33 TPM 2.0.
* **Throughput Capacity:** Up to $1{,}250{,}000\text{ EPS}$ sustained; $14.88\text{ Mpps}$ line-rate packet drops.

---

## 3. Model V-Edge: Virtualized Hypervisor Edge Appliance

Designed for private cloud datacenters, virtual SCADA testbeds, and edge VMware deployments.

* **Supported Hypervisors:** VMware vSphere ESXi 8.0+, KVM/QEMU, Proxmox VE 8.x.
* **Minimum Virtual Sizing:**
  * 4 Virtual CPUs (vCPU) with CPU Host Passthrough enabled.
  * 8 GB Assigned RAM (100% Reserved, zero memory ballooning).
  * 64 GB Virtual Disk on fast NVMe storage.
  * Virtual Network Adapter: `vmxnet3` (VMware) or `virtio-net` (KVM).
  * Hardware Attestation: Virtual TPM (vTPM) 2.0 enabled in VM settings.

