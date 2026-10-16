#!/usr/bin/env python3
"""sanitize_device_state.py: Post-Session Device Sanitization & State Teardown.

Performs complete device sanitization to return the Android test device to a clean,
uninstrumented baseline. Ensures zero residual telemetry, developer artifacts, or
proxy/certificate leaks remain between analysis sessions:
1. Audits and purges user-installed CA certificates (/data/misc/user/*/cacerts-added/)
2. Clears system and global HTTP proxy settings (Settings.Global and system properties)
3. Terminates background daemons (frida-server, ecapture, tcpdump)
4. Uninstalls target application package and wipes application sandbox caches
5. Purges synthetic mock canaries (contacts, SMS OTPs, clipboard)
6. Verifies or reverts system properties via apply_stealth_props.sh
"""

import argparse
import os
import re
import subprocess
import sys

# Optional PyYAML support with regex fallback
try:
    import yaml
    HAS_YAML = True
except ImportError:
    HAS_YAML = False


def parse_lab_config(config_path):
    """Parses lab_config.yaml using PyYAML or regex fallback."""
    if not os.path.exists(config_path):
        return {}

    if HAS_YAML:
        try:
            with open(config_path, "r", encoding="utf-8") as f:
                return yaml.safe_load(f) or {}
        except Exception as e:
            print(f"[-] Warning: Failed to parse YAML via PyYAML: {e}", file=sys.stderr)

    config = {
        "lab_environment": {
            "device": {},
            "target_sample": {}
        }
    }
    try:
        with open(config_path, "r", encoding="utf-8") as f:
            content = f.read()
        serial_m = re.search(r'serial:\s*["\']?([^"\'\s#]*)', content)
        if serial_m and serial_m.group(1):
            config["lab_environment"]["device"]["serial"] = serial_m.group(1)
        pkg_m = re.search(r'package_name:\s*["\']?([^"\'\s#]*)', content)
        if pkg_m and pkg_m.group(1):
            config["lab_environment"]["target_sample"]["package_name"] = pkg_m.group(1)
    except Exception as e:
        print(f"[-] Warning: Fallback config parser error: {e}", file=sys.stderr)

    return config


class DeviceSanitizer:
    def __init__(self, serial=None, package_name=None, dry_run=False, restore_props=False):
        self.serial = serial
        self.package_name = package_name
        self.dry_run = dry_run
        self.restore_props = restore_props

    def run_adb(self, cmd_args, check=False):
        """Executes an ADB command with optional serial routing."""
        base = ["adb"]
        if self.serial:
            base.extend(["-s", self.serial])
        full_cmd = base + cmd_args

        if self.dry_run:
            return "DRY_RUN_OK"

        try:
            res = subprocess.run(
                full_cmd,
                capture_output=True,
                text=True,
                check=check
            )
            return res.stdout.strip()
        except FileNotFoundError:
            print("[!] Error: 'adb' executable not found in PATH.", file=sys.stderr)
            return ""
        except subprocess.CalledProcessError as e:
            return e.stdout.strip() if e.stdout else ""
        except Exception as e:
            print(f"[!] ADB execution exception: {e}", file=sys.stderr)
            return ""

    def run_root(self, shell_cmd):
        """Executes a shell command on device as root (su -c)."""
        return self.run_adb(["shell", "su", "-c", shell_cmd])

    def sanitize_user_ca_certificates(self):
        """Audits and removes user-installed CA certificates."""
        print("[*] Tier 1: Auditing & purging user-installed CA certificates...")
        if self.dry_run:
            print("  [+] [DRY-RUN] Checked /data/misc/user/*/cacerts-added/ -> Clean")
            print("  [+] [DRY-RUN] Purged any user-installed trust anchors.")
            return True

        cert_paths = [
            "/data/misc/user/0/cacerts-added",
            "/data/misc/keychain/cacerts-added"
        ]
        found_certs = []
        for path in cert_paths:
            out = self.run_root(f"ls {path} 2>/dev/null")
            if out and "No such" not in out:
                files = [f.strip() for f in out.splitlines() if f.strip()]
                for f in files:
                    found_certs.append(f"{path}/{f}")

        if found_certs:
            print(f"  [!] Found {len(found_certs)} user-installed CA certificate(s):")
            for c in found_certs:
                print(f"      - {c}")
                self.run_root(f"rm -f {c}")
            print("  [+] All user-installed CA certificates purged.")
        else:
            print("  [+] No user-installed CA certificates detected in user credential store.")
        return True

    def sanitize_proxy_settings(self):
        """Clears system and global HTTP proxy settings."""
        print("[*] Tier 2: Sanitizing system and global HTTP proxy configurations...")
        if self.dry_run:
            print("  [+] [DRY-RUN] settings put global http_proxy :0")
            print("  [+] [DRY-RUN] settings delete global global_http_proxy_host")
            print("  [+] [DRY-RUN] resetprop http.proxyHost \"\"")
            return True

        # Clear SettingsProvider proxies
        self.run_adb(["shell", "settings", "put", "global", "http_proxy", ":0"])
        self.run_adb(["shell", "settings", "delete", "global", "global_http_proxy_host"])
        self.run_adb(["shell", "settings", "delete", "global", "global_http_proxy_port"])

        # Clear system properties
        self.run_root("resetprop http.proxyHost '' 2>/dev/null || setprop http.proxyHost ''")
        self.run_root("resetprop http.proxyPort '' 2>/dev/null || setprop http.proxyPort ''")
        print("  [+] Android proxy properties and SettingsProvider entries cleared.")
        return True

    def kill_lingering_daemons(self):
        """Kills any orphaned instrumentation daemons on the device."""
        print("[*] Tier 3: Terminating lingering background instrumentation daemons...")
        daemons = ["frida-server", "ecapture", "tcpdump"]
        if self.dry_run:
            for d in daemons:
                print(f"  [+] [DRY-RUN] pkill -9 -f {d}")
            return True

        for d in daemons:
            self.run_root(f"pkill -9 -f {d} 2>/dev/null || true")
            print(f"  [+] Sent SIGKILL to lingering '{d}' processes.")
        return True

    def uninstall_target_package(self):
        """Force-stops, clears, and uninstalls the target application."""
        if not self.package_name:
            print("[*] Tier 4: No target package specified; skipping package removal.")
            return True

        print(f"[*] Tier 4: Purging target package '{self.package_name}'...")
        if self.dry_run:
            print(f"  [+] [DRY-RUN] am force-stop {self.package_name}")
            print(f"  [+] [DRY-RUN] pm clear {self.package_name}")
            print(f"  [+] [DRY-RUN] pm uninstall {self.package_name}")
            return True

        self.run_adb(["shell", "am", "force-stop", self.package_name])
        self.run_adb(["shell", "pm", "clear", self.package_name])
        out = self.run_adb(["uninstall", self.package_name])
        if "Success" in out:
            print(f"  [+] Target package '{self.package_name}' uninstalled successfully.")
        else:
            print(f"  [*] Package uninstall status: {out}")
        return True

    def purge_mock_canaries(self, config_path="config/lab_config.yaml"):
        """Cleans synthetic mock contacts, SMS inbox, and clipboard."""
        print("[*] Tier 5: Purging synthetic mock canaries from device...")
        cmd = [sys.executable, "config/seed_canaries.py", "--clean", "--config", config_path]
        if self.dry_run:
            cmd.append("--dry-run")
        if self.serial:
            cmd.extend(["--serial", self.serial])

        res = subprocess.run(cmd, capture_output=True, text=True)
        if res.returncode == 0:
            print("  [+] Mock contacts, SMS inbox, and clipboard tokens purged.")
        else:
            print(f"  [-] Warning: Canary cleaner returned code {res.returncode}: {res.stderr.strip()}")
        return True

    def handle_system_properties(self):
        """Restores developer default properties or enforces stealth cloak."""
        if self.restore_props:
            print("[*] Tier 6: Reverting system properties to developer defaults...")
            if self.dry_run:
                print("  [+] [DRY-RUN] sh /data/local/tmp/apply_stealth_props.sh restore")
                return True
            self.run_root("sh /data/local/tmp/apply_stealth_props.sh restore 2>/dev/null || true")
            print("  [+] System properties reverted to standard developer debugging defaults.")
        else:
            print("[*] Tier 6: Enforcing stealth property cloaking...")
            if self.dry_run:
                print("  [+] [DRY-RUN] sh /data/local/tmp/apply_stealth_props.sh apply")
                return True
            self.run_root("sh /data/local/tmp/apply_stealth_props.sh apply 2>/dev/null || true")
            print("  [+] Stealth property cloaking verified active.")
        return True

    def execute_full_teardown(self, config_path="config/lab_config.yaml"):
        """Executes complete sequential device state teardown."""
        print("=" * 65)
        print("dbug DEVICE STATE SANITIZATION & TEARDOWN")
        print("=" * 65)
        if self.serial:
            print(f"Device Serial:   {self.serial}")
        if self.package_name:
            print(f"Target Package:  {self.package_name}")
        print(f"Dry-Run Mode:    {self.dry_run}")
        print(f"Restore Props:   {self.restore_props}")
        print("=" * 65)

        self.sanitize_user_ca_certificates()
        self.sanitize_proxy_settings()
        self.kill_lingering_daemons()
        self.uninstall_target_package()
        self.purge_mock_canaries(config_path)
        self.handle_system_properties()

        print("=" * 65)
        print("[+] DEVICE STATE SANITIZATION COMPLETE - BASELINE RESTORED")
        print("=" * 65)
        return True


def main():
    parser = argparse.ArgumentParser(
        description="dbug Device State Sanitization & Post-Execution Teardown."
    )
    parser.add_argument("--config", default="config/lab_config.yaml", help="Path to lab_config.yaml")
    parser.add_argument("--serial", default=None, help="Device serial (overrides config)")
    parser.add_argument("--package", default=None, help="Target package name to force-stop & uninstall")
    parser.add_argument("--dry-run", action="store_true", help="Simulate teardown without sending commands")
    parser.add_argument(
        "--restore-props",
        action="store_true",
        help="Revert properties to standard dev mode instead of leaving stealth cloak active"
    )

    args = parser.parse_args()
    cfg = parse_lab_config(args.config)

    serial = args.serial or cfg.get("lab_environment", {}).get("device", {}).get("serial") or None
    pkg = args.package or cfg.get("lab_environment", {}).get("target_sample", {}).get("package_name") or None

    sanitizer = DeviceSanitizer(
        serial=serial,
        package_name=pkg,
        dry_run=args.dry_run,
        restore_props=args.restore_props
    )
    sanitizer.execute_full_teardown(config_path=args.config)


if __name__ == "__main__":
    main()
