# dbug: Automated Stealth Android Dynamic Analysis, Threat Intelligence & AppSec Toolkit

`dbug` is a modular, zero-trace dynamic analysis, network-interception, and application security platform designed for observing evasive Android infostealers and auditing commercial applications protected by Runtime Application Self-Protection (RASP).

---

## 1. Core Architectural Innovation: Zero-Trace Out-of-Band Interception

Modern Android targets—both evasive malware (infostealers, banking trojans) and heavily protected commercial apps (fintech, banking, digital identity, healthcare)—deploy aggressive anti-analysis and anti-tamper mechanisms:
- They check for developer settings and USB debugging (`Settings.Global.ADB_ENABLED`, `ro.debuggable`, `sys.usb.state`).
- They check for attached debuggers (`TracerPid`).
- They detect proxy configurations (`http.proxyHost`) and VPN interfaces (`tun0`).
- They enforce strict X.509 TLS certificate pinning, rejecting custom user CA certificates installed in the Android trust store.

Traditional analysis tools (Burp Suite proxy, HTTP Toolkit VPN, Zygisk Frida scripts) trip these detection vectors, causing the application to crash, refuse connections, or route traffic to decoy endpoints.

### How `dbug` Solves This:
1. **Pre-Spawn Property Cloaking:** Uses `resetprop` (Magisk/KernelSU/APatch) to report stock production values (`ro.debuggable=0`, `ro.secure=1`, `sys.usb.state=mtp`) while keeping the `adbd` transport daemon alive. LSPosed `HideDevMode` spoofs `Settings.Global` at the `system_server` Binder level so target apps read `adb_enabled=0`.
2. **Zero-Footprint Network Interception:** Operates a dedicated Linux Wi-Fi access point (`ap0`) with transparent iptables routing. Raw L3/L4 packets and DNS queries are captured externally with `tcpdump` without setting any Android proxy or VPN.
3. **Out-of-Band TLS Decryption via Kernel eBPF:** Uses `eCapture` to attach Linux kernel eBPF uprobes to Conscrypt (`/apex/com.android.conscrypt/lib64/libssl.so`). It extracts TLS master secrets (`sslkey.log`) and decrypted packet streams directly from memory before encryption, bypassing X.509 certificate pinning with zero in-process tampering.

---

## 2. Three First-Class Operational Profiles

`dbug` treats malware analysis, regulatory privacy compliance, and commercial application security as equal first-class citizens:

```text
+-------------------------------------------------------------------------------------------------+
|                                 dbug Unified Stealth Engine                                      |
|  [resetprop Cloaking]   [Linux AP Gateway (ap0)]   [eBPF libssl.so Uprobes]   [Canary Seeding]  |
+------------------------------------------------+------------------------------------------------+
                                                 |
         +---------------------------------------+---------------------------------------+
         |                                       |                                       |
+--------v--------+                     +--------v--------+                     +--------v--------+
|    Profile:     |                     |    Profile:     |                     |    Profile:     |
|    MALWARE      |                     |    PRIVACY      |                     |     APPSEC      |
+-----------------+                     +-----------------+                     +-----------------+
| • C2 Extraction |                     | • Ad SDK Audit  |                     | • OWASP MASVS   |
| • STIX 2.1 JSON |                     | • Tracker Cat.  |                     | • OpenAPI 3.0   |
| • YARA Rules    |                     | • GDPR/CCPA     |                     | • Interactive   |
| • Attribution   |                     | • PII Exfil     |                     | • Fuzzing Prep  |
+-----------------+                     +-----------------+                     +-----------------+
```

### Profile 1: `malware` (Adversarial Threat Intelligence)
- **Objective:** Triage evasive infostealers, banking trojans, and RATs.
- **Engines:** C2 transport framing reconstruction (`c2_protocol_decoder.py`), behavioral family attribution (`family_classifier.py`), automated defensive YARA rule generation (`yara_generator.py`), and STIX 2.1 JSON bundle export (`ioc_extractor.py`).
- **Deliverables:** `threat_report_stix21.json`, `C2_PROTOCOL.md`, `FAMILY_ATTRIBUTION.json`, `IOCS.json`, and YARA signatures.

### Profile 2: `privacy` (Regulatory Compliance & Ad-Tracker Auditor)
- **Objective:** Audit commercial applications and ad-supported apps for undisclosed personal data harvesting.
- **Engines:** Resolves decrypted HTTP flows against `config/tracker_catalog.json` (taxonomy of Meta Graph, AppsFlyer, Adjust, Kochava, TikTok Pangle, Google AdMob, Unity Ads, etc.). Correlates synthetic canary exfiltration hits (`CANARY_EXFIL_HITS.json`) to prove non-consensual transmission of contacts, SMS OTPs, clipboard data, and wallet credentials.
- **Deliverables:** `PRIVACY_AUDIT.md` (citing GDPR Article 5/6 and CCPA Section 1798.100) and `privacy_findings.json`.

### Profile 3: `appsec` (Commercial Penetration Testing & API Reverse-Engineering)
- **Objective:** Penetration testing against RASP-protected commercial apps (banking, fintech, e-commerce) without triggering anti-tamper defenses.
- **Engines:** OWASP MASVS cryptographic audit (detects `AES/ECB`, static IVs, deprecated ciphers, cleartext HTTP) and automated OpenAPI 3.0 specification synthesis (`openapi_spec.json`).
- **Interactive Mode:** Supports `--interactive` flag allowing human analysts to complete MFA logins and navigate complex UI flows while zero-trace capture runs in the background.
- **Deliverables:** `API_SECURITY_REPORT.md` and `openapi_spec.json` (ready for import into Burp Suite, Postman, or OWASP ZAP).

### Profile 4: `all` (Universal Dynamic Assessment)
- Executes all engines simultaneously and synthesizes a comprehensive Executive Assessment (`REPORT.md`) covering Threat Intelligence, Privacy Compliance, and Application Security.

---

## 3. Repository Architecture

```text
dbug/
├── config/
│   ├── lab_config.yaml                 # Network, device serial, and analysis profile settings
│   ├── mock_canaries.json              # High-entropy synthetic credentials, SMS OTPs, contacts
│   ├── seed_canaries.py                # Injects and wipes canary data on test phone
│   └── tracker_catalog.json            # Curated mobile advertising, analytics & tracking taxonomy
├── device_cloaking/
│   ├── apply_stealth_props.sh          # Magisk resetprop script for ro.debuggable and sys.usb.state
│   └── verify_stealth_state.py         # Pre-flight audit asserting zero proxy, no tun0, masked ADB
├── network_capture/
│   ├── gateway_setup.sh                # Linux Wi-Fi AP hotspot + iptables transparent routing
│   ├── ecapture_runner.py              # Manages eBPF Conscrypt libssl.so uprobes
│   └── sinkhole_inetsim.conf           # Local INetSim sinkhole configuration
├── instrumentation/
│   ├── agent/
│   │   ├── bypass_antidebug.js         # Settings.Global & Debug fallback hooks
│   │   ├── crypto_dumper.js            # Hooks Cipher.init() & doFinal() for pre-encryption buffers
│   │   └── socket_tracer.js            # Hooks InetAddress, URL, and libc connect()/send()
│   └── frida_loader.py                 # Stealth loader on non-default port (38921)
├── parser_correlator/
│   ├── pcap_decryptor.py               # Combines gateway PCAP with eCapture sslkey.log
│   ├── canary_hunter.py                # Scans memory dumps and PCAP streams for canary leakage
│   ├── privacy_auditor.py              # Correlates flows with tracker catalog & evaluates GDPR/CCPA
│   ├── appsec_auditor.py               # OWASP MASVS crypto auditor & OpenAPI 3.0 generator
│   ├── c2_protocol_decoder.py          # Decodes custom C2 wire framing
│   ├── family_classifier.py            # Behavioral heuristic family attribution
│   ├── yara_generator.py               # Synthesizes defensive YARA detection rules
│   └── ioc_extractor.py                # Extracts C2 IOCs and STIX 2.1 threat bundle
├── orchestrator.py                     # Master CLI driving full automated pipeline
├── targets/<target_id>/                # Canonical per-target workspace (G0-G5 artifacts)
├── docs/
│   ├── steps.md                        # Chronological engineering steps log
│   └── SOP.md                          # Standard Operating Procedures & runbook
└── tests/
    └── test_framework_e2e.py           # 16-suite end-to-end regression test harness
```

---

## 4. Quickstart Guide

### 4.1. Pre-Flight Verification
Always verify the physical test device's stealth state before launching any target:
```bash
python3 device_cloaking/verify_stealth_state.py --config config/lab_config.yaml
```
*If any check fails, do NOT launch the application.*

### 4.2. Run Malware Dynamic Analysis (`profile: malware`)
```bash
python3 orchestrator.py \
    --apk samples/malware_sample.apk \
    --profile malware \
    --duration 120
```

### 4.3. Run Commercial App Privacy Audit (`profile: privacy`)
```bash
python3 orchestrator.py \
    --package com.example.commercial \
    --profile privacy \
    --duration 120
```

### 4.4. Run Commercial AppSec Pen-Testing & OpenAPI Export (`profile: appsec`)
Launch in interactive mode so you can perform login and MFA on the physical device:
```bash
python3 orchestrator.py \
    --package com.example.fintech \
    --profile appsec \
    --interactive
```
Press `Enter` when testing is complete. The tool will stop captures, pull TLS keys, audit cryptography, and generate `openapi_spec.json`.

### 4.5. Run Universal Full Assessment (`profile: all`)
```bash
python3 orchestrator.py \
    --package com.example.app \
    --profile all \
    --duration 120
```

### 4.6. Dry-Run Simulation Mode (No Physical Device Required)
To validate the complete pipeline offline:
```bash
python3 orchestrator.py --dry-run --profile all
```

---

## 5. Automated Regression Test Suite

The repository includes a 16-suite test harness verifying all gates, parsers, classifiers, and operational profiles:
```bash
python3 tests/test_framework_e2e.py
```
Expected output:
```text
................
----------------------------------------------------------------------
Ran 16 tests in 5.1s

OK
```

---

## 6. Ground Rules & Operational Safety

1. **Defensive Authorized Research Only:** Run strictly on dedicated hardware owned by the analyst.
2. **Synthetic Canaries Only:** Never populate the test device with real accounts or credentials. Use `seed_canaries.py`.
3. **Zero Untrusted Binaries Committed:** Raw APKs, DEX files, and ELF binaries are never committed to git.
4. **No Emoji:** Plain ASCII punctuation only across all logs, scripts, and documentation.
5. **Strict Evidence Tagging:** Every factual claim carries an evidence tag (`[C]`, `[D]`, `[M]`, `[N]`, `[E]`, `[I]`).
