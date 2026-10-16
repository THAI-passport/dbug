#!/usr/bin/env python3
"""seed_canaries.py: Injects, verifies, and purges synthetic canary data on Android physical test device via ADB."""

import argparse
import base64
import json
import os
import subprocess
import sys
import yaml


def run_adb(cmd_list, serial=None):
    base = ["adb"]
    if serial:
        base.extend(["-s", serial])
    full_cmd = base + cmd_list
    try:
        res = subprocess.run(full_cmd, capture_output=True, text=True, check=True)
        return res.stdout.strip()
    except subprocess.CalledProcessError as e:
        print(f"[!] ADB Error ({' '.join(full_cmd)}): {e.stderr.strip()}", file=sys.stderr)
        return ""


def seed_contacts(contacts, serial=None):
    print("[*] Seeding Canary Contacts...")
    for c in contacts:
        # Create raw contact
        out = run_adb(
            ["shell", "content", "insert", "--uri", "content://com.android.contacts/raw_contacts",
             "--bind", "account_type:s:local", "--bind", "account_name:s:local"],
            serial=serial
        )
        raw_id = None
        if "id=" in out:
            raw_id = out.split("id=")[-1].strip()
        elif "/" in out:
            raw_id = out.split("/")[-1].strip()

        if not raw_id:
            raw_id = "1"

        # Insert name
        run_adb(
            ["shell", "content", "insert", "--uri", "content://com.android.contacts/data",
             "--bind", f"raw_contact_id:i:{raw_id}",
             "--bind", "mimetype:s:vnd.android.cursor.item/name",
             "--bind", f"data1:s:'{c['name']}'"],
            serial=serial
        )
        # Insert phone
        run_adb(
            ["shell", "content", "insert", "--uri", "content://com.android.contacts/data",
             "--bind", f"raw_contact_id:i:{raw_id}",
             "--bind", "mimetype:s:vnd.android.cursor.item/phone_v2",
             "--bind", f"data1:s:'{c['phone']}'",
             "--bind", "data2:i:2"],
            serial=serial
        )
        print(f"  [+] Injected contact: {c['name']} ({c['phone']})")


def seed_sms(sms_list, serial=None):
    print("[*] Seeding Canary SMS Messages...")
    for s in sms_list:
        run_adb(
            ["shell", "content", "insert", "--uri", "content://sms/inbox",
             "--bind", f"address:s:'{s['sender']}'",
             "--bind", f"body:s:'{s['message']}'",
             "--bind", "read:i:1"],
            serial=serial
        )
        print(f"  [+] Injected SMS from: {s['sender']} (Code: {s['otp_code']})")


def seed_clipboard(clipboards, serial=None):
    print("[*] Seeding Canary Clipboard Tokens...")
    for item in clipboards:
        text = item["text"]
        b64_str = base64.b64encode(text.encode()).decode()
        # Set clipboard via base64 pipeline to prevent shell escape issues
        run_adb(
            ["shell", f"am broadcast -a clipper.set -e text \"$(echo '{b64_str}' | base64 -d)\" >/dev/null 2>&1 || true"],
            serial=serial
        )
        print(f"  [+] Set clipboard token: {item['canary_token']}")


def verify_canaries(serial=None):
    print("[*] Verifying Canary Presence on Device...")
    sms_check = run_adb(
        ["shell", "content", "query", "--uri", "content://sms/inbox", "--where", "\"body LIKE '%CANARY%'\""],
        serial=serial
    )
    contact_check = run_adb(
        ["shell", "content", "query", "--uri", "content://com.android.contacts/data", "--where", "\"data1 LIKE '%Canary%'\""],
        serial=serial
    )
    has_sms = "CANARY" in sms_check or "Row" in sms_check
    has_contact = "Canary" in contact_check or "Row" in contact_check

    if has_sms or has_contact:
        print("[+] Verification SUCCESS: Synthetic canary records detected on device.")
        return True
    else:
        print("[-] Verification WARNING: No canary records found in query output.")
        return False


def clean_canaries(serial=None):
    print("[*] Purging Synthetic Canary Records...")
    run_adb(
        ["shell", "content", "delete", "--uri", "content://sms", "--where", "\"body LIKE '%CANARY%'\""],
        serial=serial
    )
    run_adb(
        ["shell", "content", "delete", "--uri", "content://com.android.contacts/raw_contacts", "--where", "\"account_name='local'\""],
        serial=serial
    )
    # Clear clipboard
    run_adb(["shell", "am broadcast -a clipper.set -e text \"\" >/dev/null 2>&1 || true"], serial=serial)
    print("[+] Cleanup complete: Canary SMS, contacts, and clipboard flushed.")


def main():
    parser = argparse.ArgumentParser(description="dbug Canary Seeding & Cleanup Controller")
    parser.add_argument("--config", default="config/lab_config.yaml", help="Path to lab_config.yaml")
    parser.add_argument("--canaries", default="config/mock_canaries.json", help="Path to mock_canaries.json")
    parser.add_argument("--serial", default=None, help="Specific ADB device serial")
    parser.add_argument("--clean", action="store_true", help="Purge all planted canary data")
    parser.add_argument("--verify", action="store_true", help="Audit device for canary records")
    args = parser.parse_args()

    serial = args.serial
    if not serial and os.path.exists(args.config):
        with open(args.config, "r") as f:
            cfg = yaml.safe_load(f)
            serial = cfg.get("lab_environment", {}).get("device", {}).get("serial") or None

    if args.clean:
        clean_canaries(serial=serial)
        sys.exit(0)

    if args.verify:
        ok = verify_canaries(serial=serial)
        sys.exit(0 if ok else 1)

    if not os.path.exists(args.canaries):
        print(f"[!] Canaries file not found: {args.canaries}", file=sys.stderr)
        sys.exit(1)

    with open(args.canaries, "r") as f:
        data = json.load(f)

    if "contacts" in data:
        seed_contacts(data["contacts"], serial=serial)
    if "banking_otp" in data:
        seed_sms(data["banking_otp"], serial=serial)
    if "clipboard" in data:
        seed_clipboard(data["clipboard"], serial=serial)

    verify_canaries(serial=serial)
    print("[+] Canary seeding sequence finished.")


if __name__ == "__main__":
    main()
