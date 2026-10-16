# Executive Threat Intelligence Report: com.example.malware

- **Sample SHA-256:** `4a8f9c01823901b2c3d4e5f6071829304a8f9c01823901b2c3d4e5f607182930`
- **Package Name:** `com.example.malware`
- **Analysis Mode:** Automated Stealth Dynamic Sandbox
- **Date:** 2026-10-16

## Executive Summary
Dynamic analysis of sample `com.example.malware` was conducted under zero-footprint stealth monitoring.
All anti-analysis cues were neutralized out-of-process via `resetprop` and LSPosed `HideDevMode`.
Network traffic was decrypted out-of-band via Linux kernel eBPF Conscrypt uprobes on `wlan0`.

## Key Deliverables & Artifacts
- **Executive Findings:** [`ANALYSIS.md`](ANALYSIS.md)
- **Extracted IOCs:** [`IOCS.json`](IOCS.json)
- **Verified Facts:** [`FACTS.md`](FACTS.md)
- **Static Audit:** [`STATIC_AUDIT.md`](STATIC_AUDIT.md)
- **STIX 2.1 Bundle:** `threat_report_stix21.json`
- **C2 Protocol Framing:** `C2_PROTOCOL.md`
- **Family Attribution:** `FAMILY_ATTRIBUTION.json`
