# Target Profile: 27b7ace4848a220c3242ffbccd2dd04710af61ba7a9cae17d119ca94065e5660

- **Target Identifier:** `com.example.malware`
- **SHA-256:** `27b7ace4848a220c3242ffbccd2dd04710af61ba7a9cae17d119ca94065e5660`
- **Classification:** Universal Dynamic Assessment (Malware Intel, Privacy & AppSec)
- **Profile Mode:** `all`
- **Execution Mode:** `virtual`
- **Intake Date:** 2026-10-17

## Gate Status Ledger

| Gate | Phase | Status | Primary Artifact |
| :--- | :--- | :--- | :--- |
| **G0** | Static Intake & Triage | PASS | `STATIC_AUDIT.md` |
| **G1** | Device Cloaking | PASS | verify_stealth_state.py PASS (Virtual Sandbox) |
| **G2** | Canary Data Seeding | PASS | `seed_canaries.py` planted mock credentials |
| **G3** | Network & eBPF Capture | PASS | gateway_setup.sh, ecapture_runner.py (Virtual Sandbox) |
| **G4** | Dynamic Instrumentation | PASS | frida_loader.py pre-encryption dumps, socket tracer (Virtual Sandbox) |
| **G5** | Correlation & IOC Report | PASS | `analysis_report.md`, `iocs.json`, `CANARY_EXFIL_HITS.json` |

## Analysis Assumptions
- Target analyzed in isolated environment with synthetic mock canaries only.
- Cloaking countermeasures applied prior to spawn: masked ro.debuggable, sys.usb.state, init.svc.adbd.
- Interception executed out-of-band via eBPF TLS uprobes and transparent Linux AP gateway.
