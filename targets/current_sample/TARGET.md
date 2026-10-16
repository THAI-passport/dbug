# Target Profile: simulated_0000000000000000000000000000000000000000000000000000000000

- **Package Name:** `com.example.malware`
- **SHA-256:** `simulated_0000000000000000000000000000000000000000000000000000000000`
- **Classification:** Universal Dynamic Assessment (Malware Intel, Privacy & AppSec)
- **Profile Mode:** `all`
- **Intake Date:** 2026-10-16

## Gate Status Ledger

| Gate | Phase | Status | Primary Artifact |
| :--- | :--- | :--- | :--- |
| **G0** | Static Intake & Triage | PASS | `STATIC_AUDIT.md` |
| **G1** | Device Cloaking | PASS | `verify_stealth_state.py` PASS; masked properties, zero tun0 |
| **G2** | Canary Data Seeding | PASS | `seed_canaries.py` planted mock credentials |
| **G3** | Network & eBPF Capture | PASS | `gateway_setup.sh`, `ecapture_runner.py` TLS master secrets |
| **G4** | Dynamic Instrumentation | PASS | `frida_loader.py` pre-encryption dumps, socket tracer |
| **G5** | Correlation & IOC Report | PASS | `analysis_report.md`, `iocs.json`, `CANARY_EXFIL_HITS.json` |

## Analysis Assumptions
- Target analyzed in isolated lab environment with synthetic mock canaries only.
- Cloaking countermeasures applied prior to spawn: masked ro.debuggable, sys.usb.state, init.svc.adbd.
- Interception executed out-of-band via eBPF TLS uprobes and transparent Linux AP gateway.
