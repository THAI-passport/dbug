# dbug Framework Fixes Ledger

Tracks "Open" and "Fixed" issues in the dbug analysis toolkit.

| Issue ID | Component | Description | Status | Resolution |
| :--- | :--- | :--- | :--- | :--- |
| FIX-001 | `config/seed_canaries.py` | Android 10+ SMS provider permission denial when invoked via standard ADB shell | FIXED | Added automatic `su -c` execution fallback and multi-method clipboard injection (`cmd clipboard`, `service call`, `clipper.set`) |
| FIX-002 | `config/lab_config.yaml` | Missing explicit `target_sample` block for target APK path and package name | FIXED | Added dedicated `target_sample` section with `apk_path` and `package_name` |
| FIX-003 | `device_cloaking/verify_stealth_state.py` | Need automated push-and-apply remediation and dry-run testing support | FIXED | Implemented `--push-and-apply`, `--restore`, and `--dry-run` simulation in auditor |
| FIX-004 | `network_capture/gateway_setup.sh` | Need portable AP setup with non-Linux / macOS dry-run support | FIXED | Implemented `--dry-run` mode and interface parameter overrides |
| FIX-005 | `network_capture/ecapture_runner.py` | eBPF buffer truncation on ungraceful shutdown | FIXED | Added SIGINT/SIGTERM handlers and `pkill -2` buffer flush sequence |
| FIX-006 | `parser_correlator/canary_hunter.py` | Evasion via Base64/hex transformations of stolen credentials | FIXED | Implemented multi-encoding permutation generator (raw, b64, hex, url) |
| FIX-007 | `orchestrator.py` | Need end-to-end multi-gate automation CLI with dry-run support | FIXED | Implemented master orchestrator executing G1-G5 pipeline end-to-end |
| FIX-008 | `sample_triage/triage_apk.py` | Need automated Gate G0 static assessment before dynamic launch | FIXED | Implemented pure Python APK/DEX unpacker and anti-analysis auditor |
| FIX-009 | `instrumentation/agent/bypass_antidebug.js` | Anti-ptrace and anti-root file access evasion checks | FIXED | Added native `ptrace(PTRACE_TRACEME)` and `/su` file access interceptors |
