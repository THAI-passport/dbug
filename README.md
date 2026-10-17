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

### 4.1. Out-of-the-Box Immediate Run (Zero Configuration)
Once you clone or fork this repository, you can start dynamic analysis immediately:
```bash
python3 orchestrator.py
```
`dbug` automatically detects the environment: if no physical Android phone is attached via ADB, it activates the **Cloud & Virtual Emulation Sandbox Engine**, executes Gates G0 through G5 on the bundled defensive mock sample (`samples/sample.apk`), and produces all threat intelligence, privacy, and appsec deliverables in seconds.

### 4.2. Zero-Phone Cloud Instance & Headless Mode
Execute analysis on any headless Linux machine (AWS EC2, Google Cloud, DigitalOcean, Docker, GitHub Codespaces) without an Android phone:
```bash
python3 orchestrator.py --apk samples/sample.apk --mode virtual --profile all
```

### 4.3. Debugging Native Executables (.elf, .so, Linux/Android Binaries)
`dbug` natively analyzes and debugs standalone native ELF executables and shared libraries:
```bash
# Debug an AArch64 or x86_64 ELF binary through Gates G0 to G5
python3 orchestrator.py --binary samples/sample_arm64.elf --profile malware

# Directly disassemble and trace native executable decryptors
python3 sample_triage/executable_debugger.py --binary samples/sample_arm64.elf --disasm
```

### 4.4. One-Command Cloud VM Provisioning
To automatically configure an Ubuntu/Debian cloud VM with all system tools, QEMU user emulation, Python packages, and mock samples:
```bash
bash scripts/setup_cloud_instance.sh
```
See [`docs/CLOUD_GUIDE.md`](docs/CLOUD_GUIDE.md) for full cloud runbooks.

### 4.5. Docker Deployment
```bash
# Build and run the cloud container
docker build -t dbug .
docker run --rm -v $(pwd)/sessions:/workspace/sessions -v $(pwd)/targets:/workspace/targets dbug

# Or via Docker Compose
docker-compose up dbug
```

### 4.6. Physical Test Device Workflow
When analyzing targets on a rooted physical Android device connected via ADB:
```bash
# 1. Pre-flight stealth verification (must pass before launching target)
python3 device_cloaking/verify_stealth_state.py --config config/lab_config.yaml

# 2. Run malware dynamic analysis
python3 orchestrator.py --apk /path/to/malware.apk --mode physical --profile malware --duration 120

# 3. Run commercial app privacy audit
python3 orchestrator.py --package com.example.commercial --mode physical --profile privacy

# 4. Interactive AppSec pen-testing (for MFA and complex UI exploration)
python3 orchestrator.py --package com.example.fintech --mode physical --profile appsec --interactive
```

---

## 5. Automated Regression Test Suite

The repository includes a 31-suite end-to-end test harness verifying all gates, parsers, classifiers, executable debuggers, and cloud operational modes:
```bash
pytest -v
# or
python3 -m unittest tests/test_framework_e2e.py
```
Expected output:
```text
31 passed in ~16s (100% PASS)
```

---

## 6. Ground Rules & Operational Safety

1. **Defensive Authorized Research Only:** Run strictly on dedicated hardware or isolated cloud/virtual sandboxes.
2. **Synthetic Canaries Only:** Never populate test environments with real accounts or credentials. Use `seed_canaries.py`.
3. **Zero Live Victim Credentials Committed:** Sensitive PCAPs and live victim credentials are never committed.
4. **No Emoji:** Plain ASCII punctuation only across all logs, scripts, and documentation.
5. **Strict Evidence Tagging:** Every factual claim carries an evidence tag (`[C]`, `[D]`, `[M]`, `[N]`, `[E]`, `[I]`).
