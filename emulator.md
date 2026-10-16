# emulator.md — Android Emulator / AVD Launch & adb-over-TCP Support

## Goal
Enable dbug dynamic analysis (Gate G4) against an Android Emulator / AVD instance over adb-over-TCP,
without requiring a physical USB-connected phone, while preserving the "debug without being detected"
posture: the emulator must not look like an emulator to the target app.

## Scope

### In scope
- `tools/emulator.py`: stdlib-Python CLI to create/start/stop an AVD headless, establish adb-over-TCP,
  apply emulator-specific stealth cloaking, and report status.
- `tools/emulator.py` subcommands: `list-avds`, `create-avd`, `start`, `connect`, `cloak`, `status`,
  `stop`, `shell`.
- `--dry-run` mode: prints intended actions without touching any emulator/adb binary.
- Integration into `orchestrator.py`: `--emulator` flag and `--serial tcp://host:port` support so the
  existing pipeline (G0-G5) targets the emulator instead of a USB device.
- Emulator stealth property profile (resetprop layer) masking QEMU/goldfish indicators.
- Wiring into `config/lab_config.yaml` (`device.emulator` block) and `config/schemas/lab_config.schema.json`.

### Out of scope
- Downloading Android SDK / system images (operator supplies `$ANDROID_HOME` and an AVD or image path).
- Google Play / Play Protect bypass beyond existing `bypass_antidebug.js` + existing cloak scripts.
- Full-system QEMU tuning beyond standard `emulator` flags provided by the Android SDK.

## Design

### 1. AVD lifecycle
- `list-avds`: parse `$ANDROID_HOME/avd/*.ini` to enumerate available AVDs.
- `create-avd <name> <system-image>`: call `avdmanager create avd` non-interactively; never wipe an
  existing AVD (safety guard).
- `start <name>`: launch `emulator -avd <name> -no-window -no-audio -no-boot-anim -port <port>`,
  poll `adb -s emulator-<port> wait-for-device` + `getprop sys.boot_completed=1`.
- `stop <name>`: `adb -s emulator-<port> emu kill` (graceful), never `adb reboot -p` factory reset.

### 2. adb-over-TCP
- After boot, run `adb -s emulator-<port> tcpip <tcp-port>` on the emulator side, then
  `adb connect 127.0.0.1:<tcp-port>` on the host. All subsequent pipeline stages address the
  device via serial `127.0.0.1:<tcp-port>` (the existing `--serial` plumbing already supports this).

### 3. Emulator stealth (the "without being detected" layer)
Apps detect emulators via QEMU/goldfish indicators. The `cloak` subcommand applies a real-device
stealth profile via `resetprop` (same Layer A model as `device_cloaking/apply_stealth_props.sh`),
overriding emulator-specific properties so the target reads a stock production device:

| Emulator indicator (detected by app) | Stealth target (real-device value) | Evidence |
|---|---|---|
| ro.kernel.qemu = 1 | removed / empty | [I] |
| qemu.hw.mainkeys = 1 | removed / empty | [I] |
| qemu.sf.lcd_density | removed / empty | [I] |
| ro.product.model = sdk_gphone... | Pixel 7 / real model | [I] |
| ro.product.brand = Google / generic | Google / real brand | [I] |
| ro.product.device = emulator / generic | real device codename | [I] |
| ro.product.name = sdk... | real product name | [I] |
| ro.hardware = goldfish / ranchu | real hardware | [I] |
| ro.build.type = eng / userdebug | user | [C] (matches apply_stealth_props.sh) |
| ro.debuggable = 1 | 0 | [C] |
| ro.build.tags = test-keys | release-keys | [C] |
| ro.build.fingerprint contains generic/sdk | real fingerprint | [I] |
| ro.build.characteristics contains default | default (nosim, etc.) adjusted | [I] |
| persist.sys.usb.config / sys.usb.config | mtp | [C] |
| init.svc.adbd = running (adb over USB) | stopped (masked) | [C] |

The profile is device-specific; the operator selects `--profile pixel7|pixel8|samsung_s23` and the
matching fingerprint/model/brand/device are applied. No claim of undetectability is made (tagged [I]).

### 4. Integration with existing cloak
- Reuses `device_cloaking/apply_stealth_props.sh` Layer A property model (resetprop) extended with
  emulator-specific properties.
- Reuses LSPosed HideDevMode (Layer B) if installed on the emulator image.
- Reuses `bypass_antidebug.js` (prctl/seccomp/sigaction/procfs open/openat variants) for in-process
  cloaking under Frida on the emulator.
- Reuses existing `sanitize_device_state.py` six-tier teardown for emulator cleanup.

### 5. Safety guards
- Headless only (`-no-window`); no GPU passthrough requirements beyond what the host provides.
- Never wipe/userdata-erase an existing AVD.
- Never factory-reset the emulator (`adb reboot -p` is forbidden).
- Dry-run mode never invokes `emulator`/`adb`/`avdmanager`.
- Requires explicit operator selection of `--emulator`; defaults remain physical-USB-first.

## Verification
- `python tools/emulator.py --help` lists subcommands.
- `bash -n`-compatible Python (stdlib only); `python3 -m py_compile tools/emulator.py`.
- `python tools/rw.py lint` -> 0 problems.
- Dry-run execution: `python tools/emulator.py start pixel7 --dry-run` prints intent, exits 0,
  touches no emulator binary.
