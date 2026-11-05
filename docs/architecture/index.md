# Architecture & Low-Level Design

`blackbox-sentinel` is designed as a modular, low-overhead appliance daemon (`sentinel`) coordinating 26 native subsystems and 30 industrial protocol dissectors.

## Section Navigation

- [Appliance Architecture](./appliance-architecture.md): Decoupled C++20 orchestrator design, subsystem layout, and fault isolation.
- [Unidirectional Pipeline](./unidirectional-pipeline.md): The 5-stage processing pipeline ensuring zero thread deadlocks.
- [Memory Safety Invariants](./memory-safety-invariants.md): Zero dynamic heap allocation on fast paths and fixed-capacity state matrices.
- [Dynamic Plugin Loader](./dynamic-plugin-loader.md): Loading 30 shared-object protocol plugins via `RTLD_LAZY | RTLD_LOCAL`.
- [Port Arbitration Model](./port-arbitration-model.md): Dual-mode port arbitration and secondary Virtual IP (VIP) binding for deception.
- [Under-the-Hood Bindings](./under-the-hood-bindings.md): Direct in-process bindings to `libxinfer.so` (Tier 1) and `libblackbox.so` (Tier 2).
