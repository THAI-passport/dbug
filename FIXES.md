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
| FIX-010 | `parser_correlator/c2_protocol_decoder.py` | Need automated C2 framing and tasking opcode reconstruction | FIXED | Implemented C2 protocol dissector outputting formal `C2_PROTOCOL.md` specification |
| FIX-011 | `parser_correlator/family_classifier.py` | Need behavioral malware family attribution from observed artifacts | FIXED | Implemented heuristic scorer matching against catalog (Ermac, CraxsRAT, SpyNote, etc.) |
| FIX-012 | `sample_triage/native_emulator.py` | Native packed string decryption routines in obfuscated `.so` libraries | FIXED | Built AArch64 emulation harness supporting Unicorn with pure-Python fallback |
| FIX-013 | `orchestrator.py` & `targets/` | Canonical workspace out-of-sync between session runs and `targets/<hash>/` | FIXED | Added `sync_canonical_target_repo()` updating `TARGET.md`, `SOURCES.md`, `FACTS.md`, `ANALYSIS.md`, `REPORT.md`, `LOG.md` |
| FIX-014 | `parser_correlator/privacy_auditor.py` | Need automated mobile ad tracker detection and GDPR/CCPA PII leak auditing | FIXED | Implemented privacy auditor using `config/tracker_catalog.json` outputting `PRIVACY_AUDIT.md` |
| FIX-015 | `parser_correlator/appsec_auditor.py` | Need OWASP MASVS crypto auditing and automated API schema export | FIXED | Implemented appsec auditor analyzing ECB modes/static IVs and exporting OpenAPI 3.0 spec |
| FIX-016 | `orchestrator.py` | Framework limited to fixed-duration automated malware runs | FIXED | Added `--profile {malware,privacy,appsec,all}` and `--interactive` mode for human testing |
| FIX-017 | `orchestrator.py` & `targets/` | Executive reports and target ledgers hardcoded for malware only | FIXED | Tailored `TARGET.md` and `REPORT.md` dynamically per active profile (privacy, appsec, all, malware) and authored `docs/SOP.md` and `README.md` |
| FIX-018 | `device_cloaking/sanitize_device_state.py` | Need dedicated post-session state sanitization & teardown script | FIXED | Implemented 6-tier device sanitizer auditing/purging user CA certs, clearing global proxy, terminating daemons, and uninstalling target app |
| FIX-019 | Repo Hygiene & `targets/` | Committed mock session clutter, repeating dummy hashes (`4a8f9c01...`), and zip-corrupting symlinks | FIXED | Purged committed mock target directories, replaced repeating dummy hashes with deterministic SHA-256, converted symlinks to files, and ignored session runs |


