# Requirements & Installation

Complete dependency inventory and per-platform installation guide for dbug.

## Supported platforms

| Platform | Status | Notes |
|---|---|---|
| Linux (Debian/Ubuntu, headless containers) | Officially supported | Primary CI target |
| macOS | Officially supported | Same Python toolchain; system tools via Homebrew |
| Windows | Paused / community | Not tested or maintained per AGENTS.md; documented here as best-effort only |

Per AGENTS.md ground rules, Linux and macOS are the supported hosts. Windows is intentionally paused: do not treat Windows instructions as verified, and keep all Python code portable (`os.path`, no shell-only syntax). Dynamic analysis (emulator/phone) requires user request and hardware the user owns.

## Dependency tiers

| Tier | What | Required for |
|---|---|---|
| 1 | Python 3.10+ + pip/venv | Everything |
| 2 | Python packages (pyyaml, frida, frida-tools, pyelftools, unicorn, capstone) | Core analysis, static parsing, emulation |
| 3 | System tools (git, unzip, curl, java/JDK, jadx, apktool, ffmpeg, tshark, adb) | Recon, hash, doctor, APK surface map |
| 4 | Android SDK (`$ANDROID_HOME`: emulator, avdmanager, adb) | Emulator / AVD launch + adb-over-TCP (`tools/emulator.py`, orchestrator `--emulator`) |
| 5 | Optional RE tools (radare2/rizin, ghidra, qiling, mitmproxy, binwalk, objection) | `rw.py doctor` reporting only; analysis works without them |

## Tier 1 — Python runtime (all platforms)

Verify:
```
python3 --version   # need 3.10+
python3 -m venv --help
```

Create the project venv (recommended):
```
python3 -m venv .venv
# Linux/macOS:
source .venv/bin/activate
# Windows (best-effort, untested):
.venv\Scripts\activate
python3 -m pip install --upgrade pip
```

## Tier 2 — Python packages (all platforms)

Install from the pinned spec:

```
python3 -m pip install -r requirements.txt
```

`requirements.txt` contents:
```
pyyaml>=6.0
frida==17.24.0
frida-tools==14.11.0
pyelftools>=0.29
unicorn>=2.0.1
capstone>=5.0.0
```

Notes:
- `frida`/`frida-tools` are pinned to versions verified working together (17.24.0 / 14.11.0). Dynamic Frida instrumentation is optional in dry-run/offline mode but required for live device/emulator instrumentation.
- `unicorn`/`capstone` are used by `emulation/jitter.py` (CPU emulation). The pure-Python fallback works without them, but install them for real emulation.
- `pyelftools` is used by static ELF/Mach-O parsing tools (`desktop_static.py`, `ios_static.py`) when deeper analysis is available.

Optional test/runtime extras (installed by `tools/setup-tools.sh`):
```
python3 -m pip install pytest bleak pillow
```

## Tier 3 — System tools

### Linux (Debian/Ubuntu)

```
sudo apt-get update
sudo apt-get install -y git unzip curl ca-certificates ffmpeg tshark adb

# JDK 17 (Adoptium Temurin) for jadx/apktool
# via apt (may be older) or the user-space installer below

# user-space RE tools (no sudo) — see tools/setup-tools.sh
bash tools/setup-tools.sh   # installs JDK 17, jadx, apktool into ~/tools and a venv
```

### macOS

```
# Xcode command line tools (git, curl, unzip)
xcode-select --install

# Homebrew packages
brew install git ffmpeg tshark android-platform-tools   # provides adb
brew install openjdk@17                                # java/JDK
echo 'export PATH="/opt/homebrew/opt/openjdk@17/bin:$PATH"' >> ~/.zprofile

# user-space RE tools
bash tools/setup-tools.sh   # installs jadx, apktool into ~/tools
```

### Windows (best-effort, untested)

Not officially supported; instructions are reference only and have not been executed.

```
# git / curl / unzip
winget install Git.Git curl.curl   # or chocolatey/scoop equivalents

# Python 3.10+ from python.org or winget
winget install Python.Python.3.11

# JDK 17 (Adoptium) + jadx + apktool manually; no automated setup-tools.sh on Windows

# Android SDK platform-tools (adb) from developer.android.com
```


## Tier 4 — Android SDK (emulator / AVD support)

Required only for `tools/emulator.py` and `orchestrator.py --emulator`.

1. Download Android Command Line Tools from https://developer.android.com/studio (command-line tools only; Android Studio not required).
2. Set `ANDROID_HOME`:
   ```
   export ANDROID_HOME="$HOME/Android/Sdk"      # Linux/macOS example
   export PATH="$ANDROID_HOME/cmdline-tools/latest/bin:$ANDROID_HOME/platform-tools:$PATH"
   ```
3. Install SDK components:
   ```
   sdkmanager "platform-tools" "emulator" "system-images;android-33;google_apis;x86_64"
   avdmanager create avd -n pixel7 -k "system-images;android-33;google_apis;x86_64" -c 4096M
   ```
4. Verify:
   ```
   which emulator avdmanager adb
   emulator -list-avds
   ```

The operator supplies `$ANDROID_HOME` and an AVD or image path; dbug never downloads vendor system images.

## Tier 5 — Optional RE tools (`rw.py doctor` reporting)

These are reported by `tools/rw.py doctor` but are not required to run the pipeline:

| Tool | Purpose | Install hint |
|---|---|---|
| radare2 / rizin | Reverse-engineering framework | `apt install rizin` / `brew install rizin` |
| ghidra | SRE framework | https://ghidra-sre.org (JDK 17+) |
| qiling | Emulation framework | `pip install qiling` |
| mitmproxy | MITM proxy fallback | `pip install mitmproxy` / `brew install mitmproxy` |
| binwalk | Firmware analysis | `apt install binwalk` / `brew install binwalk` |
| objection | Frida mobile runtime | `pip install objection` |

## One-shot user-space installer (Linux/macOS)

`tools/setup-tools.sh` installs JDK 17, jadx, apktool, and a venv without sudo:

```
# default: JDK, jadx, apktool, venv + pytest/bleak/pillow
bash tools/setup-tools.sh

# with emulation extras (unicorn, capstone, pyelftools); a failed build is reported, not fatal
bash tools/setup-tools.sh --emulation   # same as --full
```

It appends `~/tools` PATH lines to `~/.bashrc`. Review the script before running; it downloads from Adoptium, GitHub (jadx/apktool), and PyPI.

## Verification

After installation, run the full check battery:

```
python tools/rw.py lint                      # 0 problems expected
python3 -m unittest discover -s tests        # OK expected (frida-gated tests skip if frida absent)
python3 -m py_compile tools/*.py *.py emulation/*.py network/*.py memory/*.py config/*.py tests/*.py
bash -n tools/*.sh device_cloaking/*.sh network_capture/*.sh
python tools/rw.py doctor                    # lists installed/missing optional tools
python tools/emulator.py list-avds --dry-run # emulator tool help path
```

Expected: lint `0 problem(s)`, tests `OK`, all compile/syntax checks pass. `doctor` will report missing optional tools (java, jadx, apktool, tshark, adb, frida, etc.) — install the tiers above as needed for your target platform.

## What is NOT required

- No vendor artifacts (APK, IPA, `.so`, firmware, dex, jar) — never committed; `rw.py lint` blocks them.
- No rooted/jailbroken device for static analysis or dry-run mode.
- No Android SDK unless using `--emulator`.
- No `unicorn`/`capstone` unless doing real CPU emulation (pure-Python fallback exists).

