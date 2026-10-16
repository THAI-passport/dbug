# dbug Framework Tooling Log

Chronological log of bugs, regressions, performance quirks, and operational observations in `dbug`'s own host tooling and scripts (`orchestrator.py`, `seed_canaries.py`, `verify_stealth_state.py`, `gateway_setup.sh`, etc.).

---

## [2026-10-16]
- **Script:** `config/seed_canaries.py`
  - **Observation:** Android 10+ restricts `content insert --uri content://sms/inbox` from standard unprivileged `shell` UID with `SecurityException` (`requires android.permission.WRITE_SMS`).
  - **Mitigation:** Implemented automatic root (`su -c`) fallback and `use_root` parameter so execution on rooted physical test phones succeeds seamlessly. Added `--dry-run` flag for offline validation.

- **Script:** `device_cloaking/verify_stealth_state.py` & `device_cloaking/apply_stealth_props.sh`
  - **Observation:** Setting `init.svc.adbd stopped` via `resetprop` masks adbd service status to user-space apps querying getprop while the kernel/adbd daemon socket remains bound and connected over USB/TCP.
  - **Mitigation:** Verified that ADB shell commands continue operating normally after masking `init.svc.adbd`. Added Layer 5 ADB transport resilience check to verify caller UID after property changes.

- **Script:** `network_capture/ecapture_runner.py`
  - **Observation:** Sending `kill -9` directly to `ecapture` truncates in-flight TLS master secrets in `sslkey.log` and produces incomplete PCAPNG headers.
  - **Mitigation:** Implemented graceful two-phase shutdown sending SIGINT (`pkill -2 ecapture`), sleeping 2 seconds to allow eBPF ring buffer sync, and falling back to SIGTERM before pulling files.

- **Script:** `instrumentation/frida_loader.py`
  - **Observation:** Connecting to standard Frida port 27042 triggers detection in infostealers querying `/proc/net/tcp`.
  - **Mitigation:** Standardized on non-default port 38921 (`hl_daemon`) across `lab_config.yaml` and `frida_loader.py`.

- **Script:** `parser_correlator/canary_hunter.py`
  - **Observation:** Stolen canary strings exfiltrated via HTTP POST are frequently Base64 or URL encoded.
  - **Mitigation:** Built multi-encoding permutation indexing that expands every canary into raw, Base64, Hex, and URL variants before scanning payloads.

- **Script:** `sample_triage/native_emulator.py`
  - **Observation:** Host workstations and headless CI environments often lack Unicorn engine binary wheels, preventing dynamic execution of native decryptor functions in `.so` files.
  - **Mitigation:** Implemented a built-in pure-Python AArch64 emulation fallback simulating register file, scratch memory, and unrolled XOR string decryption loops, enabling 100% offline verification.

- **Script:** `orchestrator.py`
  - **Observation:** Analysis artifacts were isolated in session timestamp folders, leaving `targets/<sample_hash>/` unpopulated.
  - **Mitigation:** Implemented `sync_canonical_target_repo()` which reconciles and writes `TARGET.md`, `SOURCES.md`, `FACTS.md`, `STATIC_AUDIT.md`, `ANALYSIS.md`, `REPORT.md`, `LOG.md`, and `IOCS.json` at the conclusion of each pipeline run.

- **Script:** `parser_correlator/privacy_auditor.py`
  - **Observation:** Commercial apps bundle diverse third-party analytics and tracking SDKs that transmit telemetry to distinct endpoints.
  - **Mitigation:** Built `config/tracker_catalog.json` with categorized domain suffixes (Meta, Google, AppsFlyer, Adjust, Kochava, TikTok, Unity) allowing automated separation of First-Party vs Third-Party tracker traffic and compliance scoring.

- **Script:** `parser_correlator/appsec_auditor.py`
  - **Observation:** Mobile API testing and fuzzing requires importing observed endpoints into Burp Suite, Postman, or OWASP ZAP.
  - **Mitigation:** Built automated OpenAPI 3.0 specification synthesis that aggregates unique paths, query parameters, HTTP methods, and JSON body templates from decrypted flows into `openapi_spec.json`.

- **Script:** `orchestrator.py` & `targets/`
  - **Observation:** `REPORT.md` and `TARGET.md` templates were hardcoded to "Executive Threat Intelligence Report" and "Android Infostealer / Banking Trojan", causing commercial AppSec and privacy audits to contain misleading malware headers.
  - **Mitigation:** Refactored `_sync_target_workspace` to inspect `self.profile` and generate tailored reports (`Executive Mobile Privacy Audit & Data Compliance Report`, `Executive Mobile Application Security & API Assessment`, or unified assessment) highlighting domain-relevant artifacts (`PRIVACY_AUDIT.md`, `openapi_spec.json`, `API_SECURITY_REPORT.md`).

## [2026-10-16] Fork v1 robustness & component integration (branch cline/vw3w3wp1)

- **Script:** device_cloaking/verify_stealth_state.py
  - **Change:** Added Layer 6 LSPosed HideDevMode module audit (package presence via pm path, enabled/disabled state via pm list packages -d, dry-run simulation, configurable hide_dev_mode_package, non-fatal unless hide_dev_mode_required: true). Layer 1 stealth properties now read from config stealth_properties block with hardcoded fallback. main() passes parsed lab config into StealthAuditor.
- **Script:** device_cloaking/apply_stealth_props.sh
  - **Change:** Documented two-layer cloaking model: resetprop property layer (Layer A) plus LSPosed HideDevMode system_server Settings.Global spoof (Layer B, dongdevcom/HideDevMode).
- **Script:** orchestrator.py
  - **Fix:** Resolved SyntaxError caused by nested single quotes in f-string (Defensive YARA rule path, formerly line 344) that blocked all orchestrator execution. Added G1 hint when hide_dev_mode_required is true.
- **Script:** config/lab_config.yaml
  - **Change:** Added telemetry.lsposed block (hide_dev_mode_package, hide_dev_mode_required, lsposed_manager_package) and stealth_properties block (target property values asserted by Layer 1).
- **Script:** tests/test_framework_e2e.py
  - **Change:** Added test_17_hide_devmode_preflight_layer covering Layer 6 dry-run behavior.
- **New:** .github/workflows/ci.yml - offline CI: py_compile all Python scripts, bash -n all shell scripts, dry-run e2e suite; no device, no network, no secrets.
- **New:** fork-v1.md - fork decision record (dbug itself as base), gate-by-gate integration plan, task checklist, acceptance criteria.
- **New:** device_cloaking/HIDEDEVMODE_INTEGRATION.md - HideDevMode install/enable/verify/remediation runbook for Gate G1 Layer B.

## [2026-10-16] Push constraint (environmental)

- `.github/workflows/ci.yml` was prepared locally and validated (workflow YAML structure reviewed; equivalent checks run locally: py_compile, bash -n, 20/20 e2e tests). It is NOT in commit 6c918d8 because `git push` to origin cline/vw3w3wp1 was rejected: the GitHub App token lacks the `workflows` permission required to create or update `.github/workflows/ci.yml` (`refusing to allow a GitHub App to create or update workflow ... without workflows permission`). A maintainer with `workflows` permission can add the workflow file manually; its contents are recorded in fork-v1.md T-06 and the prior commit diff.

## [2026-10-16] Frida runtime instrumentation hardening (Gate G4)

- **Script:** instrumentation/frida_loader.py
  - **Change:** Added connection retry with backoff (5 attempts, 2s delay), stealth port validation (refuses default port 27042; mandates 38921), Frida client version reporting, daemon-name config from lab_config.yaml telemetry.frida.remote_daemon_name, and remediation guidance pointing to frida_server_setup.sh. run() aborts on default port; _connect_with_retry() used for remote device connection.
- **Script:** device_cloaking/frida_server_setup.sh
  - **New:** Device-side Frida server manager: install (push + rename to hl_daemon + chmod), start (port 38921), stop, status. Supports --dry-run, --binary, --port, --name, --serial.
- **Script:** config/lab_config.yaml
  - **Change:** Added telemetry.frida.frida_server_binary field for host path to Android ARM64 frida-server binary.
- **Script:** tests/test_framework_e2e.py
  - **Change:** Added test_18 (frida client importable + version), test_19 (frida_server_setup.sh bash -n), test_20 (stealth port constants present). Suite now 20 tests.
- **Host:** Installed frida 17.24.0 Python client via pip (frida package imports and get_device_manager available).



