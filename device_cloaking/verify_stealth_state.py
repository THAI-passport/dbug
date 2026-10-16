#!/usr/bin/env python3
"""verify_stealth_state.py: Pre-flight audit asserting clean production state on Android lab device."""

import argparse
import os
import subprocess
import sys
import yaml


def adb_shell(cmd, serial=None):
    base = ["adb"]
    if serial:
        base.extend(["-s", serial])
    base.extend(["shell", cmd])
    try:
        res = subprocess.run(base, capture_output=True, text=True, check=True)
        return res.stdout.strip()
    except subprocess.CalledProcessError as e:
        return ""


def run_audit(serial=None):
    print("=" * 60)
    print("[*] STARTING PRE-FLIGHT STEALTH STATE AUDIT")
    print("=" * 60)
    failures = []
    warnings = []

    # 1. System Properties Verification
    expected_props = {
        "ro.debuggable": "0",
        "ro.secure": "1",
        "sys.usb.state": "mtp",
        "sys.usb.config": "mtp",
        "init.svc.adbd": "stopped"
    }

    print("[*] Step 1: Auditing System Properties via getprop...")
    for prop, exp in expected_props.items():
        actual = adb_shell(f"getprop {prop}", serial=serial)
        if actual != exp:
            failures.append(f"Property mismatch: '{prop}' is '{actual}' (expected '{exp}')")
        else:
            print(f"  [+] {prop} = {actual} (PASS)")

    # 2. Android Settings.Global Inspection
    print("[*] Step 2: Auditing Settings.Global Developer Flags...")
    adb_setting = adb_shell("settings get global adb_enabled", serial=serial)
    dev_setting = adb_shell("settings get global development_settings_enabled", serial=serial)
    if adb_setting not in ("0", "null", ""):
        failures.append(f"Settings.Global.adb_enabled is '{adb_setting}' (expected '0' or unexposed)")
    else:
        print(f"  [+] Settings.Global.adb_enabled = {adb_setting} (PASS)")

    if dev_setting not in ("0", "null", ""):
        warnings.append(f"Settings.Global.development_settings_enabled is '{dev_setting}' (recommend '0')")
    else:
        print(f"  [+] Settings.Global.development_settings_enabled = {dev_setting} (PASS)")

    # 3. Network Environment Audit (No VPN or Proxy)
    print("[*] Step 3: Auditing Network Interfaces for VPN Artifacts...")
    links = adb_shell("ip -o link show 2>/dev/null | awk -F': ' '{print $2}'", serial=serial).split()
    for iface in links:
        if iface.startswith(("tun", "ppp")):
            failures.append(f"Forbidden VPN network interface detected: '{iface}'")
    if not any("tun" in i or "ppp" in i for i in links):
        print(f"  [+] No VPN interfaces detected across: {', '.join(links)} (PASS)")

    proxy = adb_shell("getprop http.proxyHost", serial=serial)
    if proxy:
        failures.append(f"Android system proxy property detected: http.proxyHost='{proxy}'")
    else:
        print("  [+] No system proxy configured (PASS)")

    # 4. Frida Port Exposure Check
    print("[*] Step 4: Auditing Port Exposure (Checking Default Frida 27042)...")
    tcp_ports = adb_shell("cat /proc/net/tcp /proc/net/tcp6 2>/dev/null", serial=serial)
    # 27042 in hex is 69A2
    if ":69A2" in tcp_ports:
        failures.append("Default Frida port 27042 (:69A2) is OPEN on device! Use stealth port 38921.")
    else:
        print("  [+] Default Frida port 27042 is CLOSED (PASS)")

    # Report Summary
    print("-" * 60)
    if warnings:
        print("[!] Warnings:")
        for w in warnings:
            print(f"  - {w}")

    if failures:
        print("[!] AUDIT FAILED - The following stealth violations must be resolved:")
        for f in failures:
            print(f"  [X] {f}")
        print("=" * 60)
        return False
    else:
        print("[+] ALL PRE-FLIGHT STEALTH CHECKS PASSED. Ready for malware launch.")
        print("=" * 60)
        return True


def main():
    parser = argparse.ArgumentParser(description="Pre-flight Stealth State Audit")
    parser.add_argument("--config", default="config/lab_config.yaml", help="Path to lab_config.yaml")
    parser.add_argument("--serial", default=None, help="ADB device serial")
    args = parser.parse_args()

    serial = args.serial
    if not serial and os.path.exists(args.config):
        with open(args.config, "r") as f:
            cfg = yaml.safe_load(f)
            serial = cfg.get("lab_environment", {}).get("device", {}).get("serial") or None

    ok = run_audit(serial=serial)
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
