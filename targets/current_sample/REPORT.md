# Executive Threat Intelligence Report: com.example.malware

- **Sample SHA-256:** `simulated_0000000000000000000000000000000000000000000000000000000000`
- **Package Name:** `com.example.malware`
- **Operational Profile:** `malware`
- **Date:** 2026-10-17

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
