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

