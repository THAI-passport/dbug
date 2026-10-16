# Target Profile: 4a8f9c01823901b2c3d4e5f6071829304a8f9c01823901b2c3d4e5f607182930

- **Package Name:** `com.example.malware`
- **SHA-256:** `4a8f9c01823901b2c3d4e5f6071829304a8f9c01823901b2c3d4e5f607182930`
- **Classification:** Android Infostealer / Banking Trojan
- **Intake Date:** 2026-10-16

## Gate Status Ledger

| Gate | Phase | Status | Primary Artifact |
| :--- | :--- | :--- | :--- |
| **G0** | Static Intake & Triage | PASS | `STATIC_AUDIT.md` |
| **G1** | Device Cloaking | READY | `verify_stealth_state.py` PASS |
| **G2** | Canary Data Seeding | READY | `seed_canaries.py` |
| **G3** | Network & eBPF Capture | READY | `gateway_setup.sh`, `ecapture_runner.py` |
| **G4** | Dynamic Instrumentation | READY | `frida_loader.py` |
| **G5** | Correlation & IOC Report | READY | `analysis_report.md`, `iocs.json` |

## Analysis Assumptions
- Target requires physical ARM64 hardware with Android 12-14.
- Target employs TLS certificate pinning and queries `ro.debuggable` and `adb_enabled`.
