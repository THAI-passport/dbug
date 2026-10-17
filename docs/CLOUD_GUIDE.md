# dbug Cloud & Headless Instance Runbook

This guide details how to operate `dbug` on cloud virtual machines (AWS EC2, Google Cloud Compute, DigitalOcean Droplets, Azure, Hetzner, GitHub Codespaces) and containerized environments without any physical Android device.

---

## 1. Zero-Phone Architecture Overview

`dbug` features a dual-mode execution engine:
- **Physical Device Mode (`--mode physical`):** Operates on a dedicated, rooted physical Android device connected via ADB with transparent Linux Wi-Fi AP gateway (`ap0`) and kernel eBPF Conscrypt uprobes (`eCapture`).
- **Cloud / Virtual Sandbox Mode (`--mode virtual` or `--cloud`):** Requires **zero physical hardware**. Automatically activates when no ADB device is detected. Executes the complete analysis pipeline (Gates G0 through G5) through CPU emulation (Unicorn / QEMU / pure-Python), virtual stealth state verification, synthetic canary exfiltration tracking, and out-of-band telemetry synthesis.

Both modes generate the exact same profile-specific deliverables:
- **Malware:** `IOCS.json`, `threat_report_stix21.json` (STIX 2.1), `C2_PROTOCOL.md`, `FAMILY_ATTRIBUTION.json`, `.yar` YARA rules.
- **Privacy:** `PRIVACY_AUDIT.md`, `privacy_findings.json` (GDPR/CCPA evaluation).
- **AppSec:** `API_SECURITY_REPORT.md`, `openapi_spec.json` (OpenAPI 3.0 specification).

---

## 2. Cloud VM Quickstart (One Command)

On a freshly launched Ubuntu 22.04 LTS or Debian 12 cloud instance:

```bash
git clone https://github.com/THAI-passport/dbug.git
cd dbug
bash scripts/setup_cloud_instance.sh
```

The setup script automatically:
1. Installs system packages (`android-tools-adb`, `qemu-user-static`, `tshark`, `tcpdump`, `python3-pip`).
2. Checks for hardware virtualization (`/dev/kvm`).
3. Installs Python dependencies (`frida`, `unicorn`, `capstone`, `pyelftools`, `pyyaml`).
4. Builds bundled test samples in `samples/`.
5. Runs an automated end-to-end self-test across all gates.

---

## 3. Running Analysis on Cloud Instances

### Analyzing Android Applications (APK)
```bash
# Run full spectrum dynamic assessment (malware + privacy + appsec)
python3 orchestrator.py --apk /path/to/target.apk --profile all

# Threat intelligence extraction only
python3 orchestrator.py --apk /path/to/target.apk --profile malware

# Commercial app privacy and GDPR/CCPA audit
python3 orchestrator.py --apk /path/to/target.apk --profile privacy

# API discovery and OWASP MASVS crypto hygiene audit
python3 orchestrator.py --apk /path/to/target.apk --profile appsec
```

### Debugging Native Executables (.elf, .so, Linux/Android Native Binaries)
`dbug` natively analyzes and debugs standalone native binaries:
```bash
# Debug an AArch64 or x86_64 ELF binary
python3 orchestrator.py --binary /path/to/malware_agent.elf --profile malware

# Directly disassemble and trace native executable decryptors
python3 sample_triage/executable_debugger.py --binary /path/to/malware_agent.elf --disasm
```

### Out-of-the-Box Immediate Run
When forking or cloning this repository, you can execute the pipeline right away without providing any arguments:
```bash
python3 orchestrator.py
```
This automatically uses the bundled defensive sample (`samples/sample.apk`), auto-detects the cloud/headless environment, and generates all analysis deliverables.

---

## 4. Docker Deployment

### Run with Docker CLI
```bash
# Build the Docker image
docker build -t dbug .

# Execute analysis in container
docker run --rm -v $(pwd)/sessions:/workspace/sessions -v $(pwd)/targets:/workspace/targets dbug
```

### Run with Docker Compose
```bash
# Start standard virtual sandbox analysis
docker-compose up dbug

# For cloud instances with /dev/kvm enabled, launch containerized Android (Redroid)
docker-compose --profile emulator up -d
adb connect 127.0.0.1:5555
docker-compose run dbug --mode physical --apk samples/sample.apk
```

---

## 5. Verification & Continuous Integration

To run the offline end-to-end test suite verifying all 26+ tests across the framework:
```bash
pytest -v
# or
python3 -m unittest tests/test_framework_e2e.py
```
