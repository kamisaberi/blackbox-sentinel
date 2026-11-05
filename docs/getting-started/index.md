# Getting Started

Welcome to the **Blackbox Sentinel (`sentinel`)** Getting Started guide. This section provides complete walkthroughs for deploying the Tier 3 edge XDR appliance daemon.

## Section Navigation

- [Overview & Mission](./overview.md): Autonomous edge active defense, $0.00 cloud egress, and the 5 operational stages.
- [Hardware Specifications](./hardware-specifications.md): S-1000 DIN-Rail, S-5000 1U Rackmount, and V-Edge hypervisor specs.
- [System Requirements](./system-requirements.md): Operating system baselines, Linux kernel capabilities, and POSIX permissions.
- [Installation](./installation.md): Deploying `.deb` packages, manual CMake builds, or importing OVA/QCOW2 images.
- [Initial Configuration](./initial-configuration.md): Minimal `sentinel.yaml` layout and SSL certificate generation for port 8443.
- [Shadow Mode Evaluation](./shadow-mode-evaluation.md): 14-day zero-risk passive SPAN/TAP evaluation (`STAGE_SHADOW_MODE`).
- [First Threat Mitigation](./first-threat-mitigation.md): Transitioning to `STAGE_FULL_ACTIVE` and verifying in-kernel drops.
- [Verifying Appliance Health](./verifying-appliance-health.md): Command-line health audits (`sentinel --health`) and Web Command Center checks.
