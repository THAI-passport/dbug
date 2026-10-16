# ROBUSTNESS_IMPLEMENTATION_PLAN.md: Comprehensive Anti-Analysis & Pipeline Hardening Specification

## Overview

This document specifies the multi-phase engineering roadmap to elevate `dbug` into a hardened, commercial-grade dynamic analysis sandbox and application security auditor. It eliminates all remaining architectural blindspots identified in [HANDOFF.md](file:///Users/puredent/Desktop/dbug/HANDOFF.md) Section 7, enabling zero-trace operation against aggressive anti-debugging heuristics, commercial RASP engines (DexGuard, Promon SHIELD, AppSealing, Arxan), and sophisticated evasive malware.

---

## Phase Matrix

| Phase | Subsystem | Target Gaps | Key Files |
| :--- | :--- | :--- | :--- |
| **Phase 1** | In-Process Anti-Debug & RASP Cloaking | Procfs `TracerPid` masking, memory maps filtering, comprehensive `Settings.Global`/`Secure`/`System` overloads, and `ApplicationInfo.FLAG_DEBUGGABLE` spoofing | [instrumentation/agent/bypass_antidebug.js](file:///Users/puredent/Desktop/dbug/instrumentation/agent/bypass_antidebug.js) |
| **Phase 2** | Cryptographic Telemetry Hardening | Streaming cipher buffers (`update`), missing `doFinal` overloads (`ByteBuffer`, 0-arg, buffer offset/length), and AES-GCM tag/IV extraction | [instrumentation/agent/crypto_dumper.js](file:///Users/puredent/Desktop/dbug/instrumentation/agent/crypto_dumper.js) |
| **Phase 3** | Static-to-Dynamic Pipeline Handoff | Disconnected triage handoff: emit structured `analysis_profile.json` in G0 and consume it in G4 for adaptive script injection | [sample_triage/triage_apk.py](file:///Users/puredent/Desktop/dbug/sample_triage/triage_apk.py)<br>[orchestrator.py](file:///Users/puredent/Desktop/dbug/orchestrator.py)<br>[instrumentation/frida_loader.py](file:///Users/puredent/Desktop/dbug/instrumentation/frida_loader.py) |
| **Phase 4** | Automated Native Emulation Integration | Standalone Unicorn/pure-Python AArch64 string decryptor wired directly into Gate G0 static assessment | [sample_triage/native_emulator.py](file:///Users/puredent/Desktop/dbug/sample_triage/native_emulator.py)<br>[sample_triage/triage_apk.py](file:///Users/puredent/Desktop/dbug/sample_triage/triage_apk.py) |
| **Phase 5** | Environment & Dependency Management | Explicit dependency declarations for host runtime, telemetry agents, and native disassemblers | [requirements.txt](file:///Users/puredent/Desktop/dbug/requirements.txt) |
| **Phase 6** | Test Suite Expansion & Verification | Automated verification across all new hooks, handoffs, and emulation paths | [tests/test_framework_e2e.py](file:///Users/puredent/Desktop/dbug/tests/test_framework_e2e.py) |

---

## Detailed Technical Specifications

### Phase 1: In-Process Anti-Debug & Anti-RASP Hardening

#### 1.1 Procfs `TracerPid` Masking
- **The Threat:** Native RASP libraries read `/proc/self/status` or `/proc/<pid>/status` using libc `openat` and `read`/`fgets`. If `TracerPid: <non-zero>` is observed, execution is aborted.
- **Implementation:** Intercept `read` and `fgets` in `libc.so`. When reading file descriptors mapped to `/proc/self/status`, inspect the buffer and rewrite `TracerPid:\t[0-9]+` to `TracerPid:\t0`.
- **Evidence Tag:** `[M]` Memory / Hook.

#### 1.2 Procfs `/proc/self/maps` Cloaking
- **The Threat:** RASP engines read `/proc/self/maps` looking for loaded shared objects such as `frida-agent.so`, `frida-gadget.so`, or thread names like `gum-js-loop`.
- **Implementation:** Intercept `openat` and redirect `/proc/self/maps` queries to a sanitized in-memory synthetic stream, or redact lines containing `frida`, `gadget`, and `gum` inside the `read` hook.
- **Evidence Tag:** `[M]` Memory / Hook.

#### 1.3 Complete `SettingsProvider` Overloads
- **The Threat:** Target applications query `Settings.Global`, `Settings.Secure`, and `Settings.System` using `getString()`, `getLong()`, or `getFloat()`, bypassing `getInt()` hooks.
- **Implementation:** Hook all method overloads in `android.provider.Settings$Global`, `Settings$Secure`, and `Settings$System` for `adb_enabled` and `development_settings_enabled`:
  - `getInt(cr, name, def)` and `getInt(cr, name)` -> `0`
  - `getString(cr, name)` -> `"0"`
  - `getLong(cr, name, def)` and `getLong(cr, name)` -> `0`
  - `getFloat(cr, name, def)` and `getFloat(cr, name)` -> `0.0`
- **Evidence Tag:** `[M]` Memory / Hook.

#### 1.4 Application Manifest `FLAG_DEBUGGABLE` Spoofing
- **The Threat:** Java code evaluates `(context.getApplicationInfo().flags & ApplicationInfo.FLAG_DEBUGGABLE) != 0`.
- **Implementation:** Hook `android.content.pm.ApplicationInfo` getters and `ContextWrapper.getApplicationInfo()` to clear bit 1 (`0x2`, `FLAG_DEBUGGABLE`) and bit 8 (`0x100`, `FLAG_TEST_ONLY`).
- **Evidence Tag:** `[M]` Memory / Hook.

---

### Phase 2: Cryptographic Extraction Hardening

#### 2.1 Full `Cipher.doFinal` Overload Coverage
- **The Threat:** Modern network stacks (OkHttp 4.x, Conscrypt, Netty) utilize Java NIO `ByteBuffer` or zero-argument `doFinal()`, completely evading simple `doFinal(byte[])` hooks.
- **Implementation:** Add Frida interceptors for:
  - `Cipher.doFinal()` (zero arguments)
  - `Cipher.doFinal(java.nio.ByteBuffer, java.nio.ByteBuffer)`
  - `Cipher.doFinal(byte[], int, int, byte[])`
  - `Cipher.doFinal(byte[], int, int, byte[], int)`
- **Evidence Tag:** `[M]` Memory / Hook.

#### 2.2 Streaming Cipher Tracking via `Cipher.update()`
- **The Threat:** Payload exfiltration encrypted in chunks via `Cipher.update()` leaves only the final block visible in `doFinal()`.
- **Implementation:** Maintain an internal map keyed by `Cipher` instance hash code. Collect chunks passed to `Cipher.update()`, and assemble the full plaintext buffer when `doFinal()` completes.
- **Evidence Tag:** `[M]` Memory / Hook.

#### 2.3 AES-GCM Parameter Extraction
- **The Threat:** AEAD ciphers (`AES/GCM/NoPadding`) pass `GCMParameterSpec` rather than `IvParameterSpec`.
- **Implementation:** Detect `javax.crypto.spec.GCMParameterSpec` during `Cipher.init()`, extracting both IV bytes and auth tag length.
- **Evidence Tag:** `[M]` Memory / Hook.

---

### Phase 3: Static-to-Dynamic Triage Handoff

#### 3.1 Structured `analysis_profile.json`
- **The Problem:** Gate G0 triage writes Markdown (`STATIC_AUDIT.md`), but dynamic stages in `orchestrator.py` cannot programmatically inspect detected cues.
- **Implementation:** Update [sample_triage/triage_apk.py](file:///Users/puredent/Desktop/dbug/sample_triage/triage_apk.py) to emit `analysis_profile.json` containing:
  - `package_name`, `sha256`, `target_sdk`
  - `detected_evasion_cues`: list of detected anti-debug and RASP strings
  - `native_libraries`: list of extracted `.so` files
  - `recommended_hooks`: tailored list of required agent scripts
  - `suspicious_permissions`: accessibility, SMS, overlay flags
  - `static_indicators`: extracted URLs, IPs, Telegram tokens
- **Evidence Tag:** `[C]` Code / Static.

#### 3.2 Adaptive Hook Injection in `frida_loader.py`
- **Implementation:** [instrumentation/frida_loader.py](file:///Users/puredent/Desktop/dbug/instrumentation/frida_loader.py) consumes `--profile-json`. If specific evasion patterns are detected (e.g. `TracerPid` or `anti_debug`), specialized hooks are activated automatically.
- **Evidence Tag:** `[C]` / `[M]`.

---

### Phase 4: Automated Native Emulation in Gate G0

#### 4.1 Native Emulator Pipeline Integration
- **The Problem:** [sample_triage/native_emulator.py](file:///Users/puredent/Desktop/dbug/sample_triage/native_emulator.py) contains an AArch64 emulation engine for obfuscated strings, but is not automatically executed.
- **Implementation:** During Gate G0, if `.so` libraries with suspicious exported symbols (e.g., `decrypt`, `init_key`, `get_c2`, `Java_*`) are discovered, [triage_apk.py](file:///Users/puredent/Desktop/dbug/sample_triage/triage_apk.py) automatically invokes the emulator to extract decrypted strings, updating `analysis_profile.json` and `STATIC_AUDIT.md`.
- **Evidence Tag:** `[C]` Code / Static / Emulation.

---

### Phase 5: Dependency Management (`requirements.txt`)

- **Implementation:** Create standard [requirements.txt](file:///Users/puredent/Desktop/dbug/requirements.txt) declaring required and optional package groups:
  - Base: `pyyaml`
  - Instrumentation: `frida`, `frida-tools`
  - Static & Native: `pyelftools`, `unicorn`, `capstone`
  - Network & Packets: `scapy`, `pyshark`

---

### Phase 6: Test Suite Expansion & Validation

- Add unit and end-to-end tests in [tests/test_framework_e2e.py](file:///Users/puredent/Desktop/dbug/tests/test_framework_e2e.py) to validate:
  - `test_20_tracerpid_procfs_spoofing`
  - `test_21_settings_provider_complete_overloads`
  - `test_22_crypto_dumper_bytebuffer_and_update`
  - `test_23_triage_analysis_profile_json_handoff`
  - `test_24_native_emulator_pipeline_integration`
- Verify 100% test pass rate across the full test suite.
