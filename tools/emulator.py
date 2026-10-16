#!/usr/bin/env python3
"""tools/emulator.py: Android Emulator / AVD launch and adb-over-TCP support.

Brings dbug dynamic analysis (Gate G4) to an Android Emulator / AVD instance
without requiring a physical USB-connected phone, while preserving the
"debug without being detected" posture: the emulator is cloaked so it does not
look like an emulator to the target application.

Stdlib only. Requires $ANDROID_HOME (emulator, avdmanager, adb) supplied by the
operator. All mutating operations honor --dry-run (print intent, exit 0, touch
no emulator/adb binary).

Usage:
    python tools/emulator.py list-avds [--dry-run]
    python tools/emulator.py create-avd <name> <system-image> [--dry-run]
    python tools/emulator.py start <name> [--port 5554] [--dry-run]
    python tools/emulator.py connect [--host 127.0.0.1] [--port 5555] [--dry-run]
    python tools/emulator.py cloak [--serial emulator-5554] [--profile pixel7] [--dry-run]
    python tools/emulator.py status [--serial emulator-5554] [--dry-run]
    python tools/emulator.py stop [--serial emulator-5554] [--dry-run]
    python tools/emulator.py shell [--serial emulator-5554] <command> [--dry-run]

Stealth profile masks QEMU/goldfish emulator indicators so the target app reads
a stock production device (ro.build.type=user, ro.debuggable=0, etc.). No claim
of undetectability is made; all emulator-specific masking is tagged [I].
"""
import argparse
import os
import shutil
import subprocess
import sys
import time

ANDROID_HOME = os.environ.get("ANDROID_HOME", "")


def _tool(name):
    """Return absolute path to an Android SDK tool, or the bare name if ANDROID_HOME unset."""
    if ANDROID_HOME:
        cand = os.path.join(ANDROID_HOME, "emulator", name)
        if os.path.isfile(cand):
            return cand
        cand = os.path.join(ANDROID_HOME, "tools", "bin", name)
        if os.path.isfile(cand):
            return cand
        cand = os.path.join(ANDROID_HOME, "platform-tools", name)
        if os.path.isfile(cand):
            return cand
    return name


def EMULATOR():
    return _tool("emulator")


def AVDMANAGER():
    return _tool("avdmanager")


def ADB():
    return _tool("adb")


def dry(msg):
    print("[DRY-RUN] " + msg)


def run(cmd, dry_run=False, capture=True):
    """Run a command, honoring dry-run. Returns CompletedProcess or None in dry-run."""
    if dry_run:
        dry(" ".join(cmd))
        return None
    try:
        if capture:
            return subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        return subprocess.run(cmd, timeout=120)
    except FileNotFoundError:
        print(f"[!] binary not found: {cmd[0]}", file=sys.stderr)
        return None
    except subprocess.TimeoutExpired as e:
        print(f"[!] command timed out: {' '.join(cmd)}", file=sys.stderr)
        return e

# --- device stealth profiles (real-device values to mask emulator indicators) ---
PROFILES = {
    "pixel7": {
        "ro.product.model": "Pixel 7",
        "ro.product.brand": "Google",
        "ro.product.manufacturer": "Google",
        "ro.product.device": "panther",
        "ro.product.name": "panther",
        "ro.hardware": "google",
        "ro.build.fingerprint": "google/panther/panther:13/TD1A.220804.009/9036018:user/release-keys",
        "ro.build.characteristics": "nosim",
    },
    "pixel8": {
        "ro.product.model": "Pixel 8",
        "ro.product.brand": "Google",
        "ro.product.manufacturer": "Google",
        "ro.product.device": "felix",
        "ro.product.name": "felix",
        "ro.hardware": "google",
        "ro.build.fingerprint": "google/felix/felix:13/TD1A.220804.009/9036018:user/release-keys",
        "ro.build.characteristics": "nosim",
    },
    "samsung_s23": {
        "ro.product.model": "SM-S918U",
        "ro.product.brand": "samsung",
        "ro.product.manufacturer": "samsung",
        "ro.product.device": "s23",
        "ro.product.name": "s23",
        "ro.hardware": "samsung",
        "ro.build.fingerprint": "samsung/s23/s23:13/TP1A.220624.014/S918UXXU1AWD2:user/release-keys",
        "ro.build.characteristics": "nosim",
    },
}

# Emulator-specific indicators to blank/remove (set to empty string so reads fail gracefully).
EMULATOR_BLANK = {
    "ro.kernel.qemu": "",
    "qemu.hw.mainkeys": "",
    "qemu.sf.lcd_density": "",
    "qemu.sf.camera.facing": "",
    "persist.sys.qemu.enabled": "",
}

# Base stealth properties shared with device_cloaking/apply_stealth_props.sh Layer A.
BASE_STEALTH = {
    "ro.build.type": "user",
    "ro.debuggable": "0",
    "ro.secure": "1",
    "ro.build.tags": "release-keys",
    "sys.usb.state": "mtp",
    "sys.usb.config": "mtp",
    "persist.sys.usb.config": "mtp",
    "init.svc.adbd": "stopped",
}


def adb_serial_cmd(serial, *args):
    return [ADB(), "-s", serial] + list(args)


def shell_resetprop(serial, prop, val, dry_run=False):
    """Set a property on the device via resetprop (preferred) or setprop fallback."""
    reset_cmd = adb_serial_cmd(serial, "shell", "resetprop", prop, val)
    res = run(reset_cmd, dry_run=dry_run)
    if dry_run:
        return True
    if res and res.returncode == 0:
        return True
    # Fallback to setprop (works for rw props without root on some builds).
    set_cmd = adb_serial_cmd(serial, "shell", "setprop", prop, val)
    res2 = run(set_cmd, dry_run=dry_run)
    if dry_run:
        return True
    return res2 is not None and res2.returncode == 0


def cloak_profile(serial, profile, dry_run=False):
    if profile not in PROFILES:
        print(f"[!] unknown profile: {profile} (choices: {', '.join(PROFILES)})", file=sys.stderr)
        return 1
    applied = 0
    props = {}
    props.update(BASE_STEALTH)
    props.update(EMULATOR_BLANK)
    props.update(PROFILES[profile])
    for prop, val in props.items():
        if shell_resetprop(serial, prop, val, dry_run=dry_run):
            applied += 1
        else:
            print(f"[!] failed to set {prop}={val}", file=sys.stderr)
    # --- subcommands ---
def cmd_list_avds(a, dry_run=False):
    avd_home = os.path.join(ANDROID_HOME, "avd") if ANDROID_HOME else ""
    if dry_run:
        dry(f"list AVDs in {avd_home}")
        return 0
    if not avd_home or not os.path.isdir(avd_home):
        print("no AVD directory (ANDROID_HOME/avd missing)")
        return 0
    avds = []
    for fn in sorted(os.listdir(avd_home)):
        if fn.endswith(".ini"):
            avds.append(fn[:-4])
    if avds:
        print("Available AVDs:")
        for name in avds:
            print(f"  {name}")
    else:
        print("no AVDs found")
    return 0


def cmd_create_avd(a, dry_run=False):
    name = a.name
    image = a.system_image
    avd_ini = os.path.join(ANDROID_HOME, "avd", name + ".ini") if ANDROID_HOME else ""
    if avd_ini and os.path.isfile(avd_ini):
        print(f"[!] AVD '{name}' already exists; refusing to overwrite (safety guard)")
        return 1
    if dry_run:
        dry(f"create AVD '{name}' from image '{image}'")
        return 0
    cmd = [AVDMANAGER(), "create", "avd", "-n", name, "-k", image, "-c", "4096M", "--force"]
    res = run(cmd, dry_run=dry_run)
    if res is None:
        return 1
    return 0 if res.returncode == 0 else 1


def _wait_boot(serial, dry_run=False, timeout=300):
    if dry_run:
        dry(f"wait for {serial} boot completion")
        return True
    deadline = time.time() + timeout
    while time.time() < deadline:
        res = run(adb_serial_cmd(serial, "shell", "getprop", "sys.boot_completed"), dry_run=False, capture=True)
        if res and res.returncode == 0 and res.stdout.strip() == "1":
            return True
        time.sleep(5)
    print(f"[!] {serial} did not report boot completion within {timeout}s", file=sys.stderr)
    return False


def cmd_start(a, dry_run=False):
    name = a.name
    port = a.port
    serial = f"emulator-{port}"
    if dry_run:
        dry(f"start AVD '{name}' headless on port {port} (serial {serial})")
        return 0
    cmd = [
        EMULATOR(), "-avd", name, "-no-window", "-no-audio", "-no-boot-anim",
        "-port", str(port),
    ]
    try:
        subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except FileNotFoundError:
        print(f"[!] emulator binary not found: {EMULATOR()}", file=sys.stderr)
        return 1
    print(f"[*] launching AVD '{name}' on port {port} ...")
    if not _wait_boot(serial, dry_run=False):
        return 1
    print(f"[+] AVD '{name}' booted (serial {serial})")
    return 0


def cmd_connect(a, dry_run=False):
    host = a.host
    port = a.port
    serial = f"{host}:{port}"
    if dry_run:
        dry(f"adb connect {host}:{port} (serial {serial})")
        return 0
    run([ADB(), "tcpip", str(port)], dry_run=False, capture=True)
    res = run([ADB(), "connect", f"{host}:{port}"], dry_run=False, capture=True)
    if res is None:
        return 1
    if res.returncode == 0 and ("connected" in res.stdout or "already" in res.stdout):
        print(f"[+] adb-over-TCP connected: {host}:{port}")
        return 0
    print(f"[!] adb connect failed: {res.stdout.strip()} {res.stderr.strip()}", file=sys.stderr)
    return 1


def cmd_cloak(a, dry_run=False):
    return cloak_profile(a.serial, a.profile, dry_run=dry_run)


def cmd_status(a, dry_run=False):
    serial = a.serial
    if dry_run:
        dry(f"report stealth status for {serial}")
        return 0
    props = list(BASE_STEALTH.keys()) + list(EMULATOR_BLANK.keys())
    if a.profile and a.profile in PROFILES:
        props += list(PROFILES[a.profile].keys())
    seen = []
    for p in props:
        if p in seen:
            continue
        seen.append(p)
    print(f"stealth property status for {serial}:")
    all_ok = True
    for p in seen:
        res = run(adb_serial_cmd(serial, "shell", "getprop", p), dry_run=False, capture=True)
        val = res.stdout.strip() if res and res.returncode == 0 else "<error>"
        print(f"  {p} = {val}")
        if p in BASE_STEALTH and val != BASE_STEALTH[p]:
            all_ok = False
    print("[+] base stealth properties verified" if all_ok else "[-] base stealth properties mismatch")
    return 0 if all_ok else 1


def cmd_stop(a, dry_run=False):
    serial = a.serial
    if dry_run:
        dry(f"stop emulator {serial} (emu kill, no factory reset)")
        return 0
    res = run(adb_serial_cmd(serial, "emu", "kill"), dry_run=False, capture=True)
    if res is None:
        return 1
def cmd_shell(a, dry_run=False):
    serial = a.serial
    cmd = adb_serial_cmd(serial, "shell", *a.command)
    if dry_run:
        dry(" ".join(cmd))
        return 0
    res = run(cmd, dry_run=False, capture=False)
    if res is None:
        return 1
    return res.returncode


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Android Emulator / AVD launch and adb-over-TCP support for dbug stealth analysis.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = ap.add_subparsers(dest="cmd", required=True)

    def add_common(p):
        p.add_argument("--serial", default="emulator-5554", help="adb serial (emulator-<port> or host:port)")
        p.add_argument("--dry-run", action="store_true", help="override global dry-run for this subcommand")

    p = sub.add_parser("list-avds", help="enumerate AVDs under $ANDROID_HOME/avd")
    p.add_argument("--dry-run", action="store_true", help="print intent; do not touch emulator/adb")
    p.set_defaults(func=cmd_list_avds)

    p = sub.add_parser("create-avd", help="create a new AVD (never overwrites existing)")
    p.add_argument("name")
    p.add_argument("system-image")
    p.add_argument("--dry-run", action="store_true", help="print intent; do not touch emulator/adb")
    p.set_defaults(func=cmd_create_avd)

    p = sub.add_parser("start", help="launch AVD headless and wait for boot")
    p.add_argument("name")
    p.add_argument("--port", type=int, default=5554, help="emulator/adb port")
    p.add_argument("--dry-run", action="store_true", help="print intent; do not touch emulator/adb")
    p.set_defaults(func=cmd_start)

    p = sub.add_parser("connect", help="adb tcpip + connect over TCP")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=5555, help="TCP port for adb-over-TCP")
    p.add_argument("--dry-run", action="store_true", help="print intent; do not touch emulator/adb")
    p.set_defaults(func=cmd_connect)

    p = sub.add_parser("cloak", help="apply emulator stealth profile (resetprop layer)")
    add_common(p)
    p.add_argument("--profile", default="pixel7", choices=list(PROFILES), help="device stealth profile")
    p.set_defaults(func=cmd_cloak)

    p = sub.add_parser("status", help="report stealth property status")
    add_common(p)
    p.add_argument("--profile", default=None, choices=list(PROFILES), help="expected profile for status")
    p.set_defaults(func=cmd_status)

    p = sub.add_parser("stop", help="stop emulator gracefully (no factory reset)")
    add_common(p)
    p.set_defaults(func=cmd_stop)

    p = sub.add_parser("shell", help="run a shell command on the emulator")
    add_common(p)
    p.add_argument("command", nargs="+")
    p.set_defaults(func=cmd_shell)

    a = ap.parse_args(argv)
    dry_run = getattr(a, "dry_run", False)
    return a.func(a, dry_run=dry_run)


if __name__ == "__main__":
    sys.exit(main())

