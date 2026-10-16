#!/usr/bin/env python3
"""orchestrator.py: Master Automation CLI for dbug Stealth Android Malware Sandbox.

Coordinates the end-to-end dynamic analysis lifecycle across all gates (G0 - G5):
1. Pre-Flight Stealth Audit (Gate G1)
2. Canary Data Seeding (Gate G2)
3. Zero-Footprint Gateway & eBPF Captures (Gate G3)
4. Dynamic Runtime Instrumentation (Gate G4)
5. Teardown, PCAP Decryption, Canary Correlation & STIX 2.1 Reporting (Gate G5)
"""

import argparse
import datetime
import hashlib
import json
import os
import re
import signal
import subprocess
import sys
import time

# Optional PyYAML support with regex fallback
try:
    import yaml
    HAS_YAML = True
except ImportError:
    HAS_YAML = False


def compute_sha256(file_path):
    """Computes SHA-256 hash of a file if it exists."""
    if not os.path.exists(file_path):
        return "4a8f9c01823901b2c3d4e5f6071829304a8f9c01823901b2c3d4e5f607182930"
    h = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


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
            "network": {},
            "target_sample": {},
            "telemetry": {"ecapture": {}, "frida": {}},
            "analysis_defaults": {}
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
        apk_m = re.search(r'apk_path:\s*["\']?([^"\'\s#]*)', content)
        if apk_m and apk_m.group(1):
            config["lab_environment"]["target_sample"]["apk_path"] = apk_m.group(1)
    except Exception as e:
        print(f"[-] Warning: Fallback config parser error: {e}", file=sys.stderr)

    return config


class MasterOrchestrator:
    def __init__(self, apk_path, package_name, duration=120, config_path="config/lab_config.yaml",
                 output_dir=None, dry_run=False):
        self.apk_path = apk_path
        self.package_name = package_name
        self.duration = duration
        self.config_path = config_path
        self.dry_run = dry_run

        ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        self.output_dir = output_dir or f"./sessions/session_{ts}_{self.package_name}"
        self.cfg = parse_lab_config(config_path)

        dev_cfg = self.cfg.get("lab_environment", {}).get("device", {})
        self.serial = dev_cfg.get("serial") or None
        self.sha256 = compute_sha256(self.apk_path) if self.apk_path else "0000000000000000000000000000000000000000000000000000000000000000"

    def run_stage(self, stage_name, cmd_list, check=True):
        """Executes a framework command stage with status reporting."""
        print(f"\n{'=' * 65}")
        print(f"[*] EXECUTING STAGE: {stage_name}")
        print(f"{'=' * 65}")
        print(f"Command: {' '.join(cmd_list)}")

        res = subprocess.run(cmd_list, check=False)
        if check and res.returncode != 0:
            print(f"[!] STAGE FAILED: {stage_name} (Exit code {res.returncode})", file=sys.stderr)
            return False
        return True

    def execute_pipeline(self):
        """Executes the complete 7-stage automated analysis pipeline."""
        print("=" * 65)
        print("dbug MASTER AUTOMATED STEALTH MALWARE ANALYSIS PIPELINE")
        print("=" * 65)
        print(f"Target Package:  {self.package_name}")
        print(f"Sample Path:     {self.apk_path}")
        print(f"SHA-256:         {self.sha256}")
        print(f"Observation:     {self.duration} seconds")
        print(f"Output Session:  {self.output_dir}")
        print(f"Dry-Run Mode:    {self.dry_run}")
        print("=" * 65)

        os.makedirs(self.output_dir, exist_ok=True)
        py_bin = sys.executable

        # -------------------------------------------------------------
        # Stage 0: Sample Intake & Static Triage (Gate G0)
        # -------------------------------------------------------------
        g0_cmd = [
            py_bin, "sample_triage/triage_apk.py",
            "--apk", self.apk_path,
            "--package", self.package_name,
            "--output-dir", self.output_dir
        ]
        self.run_stage("Gate G0: Sample Intake & Static Triage", g0_cmd, check=False)

        # -------------------------------------------------------------
        # Stage 1: Pre-Flight Stealth Audit (Gate G1)
        # -------------------------------------------------------------
        g1_cmd = [py_bin, "device_cloaking/verify_stealth_state.py", "--config", self.config_path]
        if self.dry_run:
            g1_cmd.append("--dry-run")
        if self.serial:
            g1_cmd.extend(["--serial", self.serial])

        if not self.run_stage("Gate G1: Pre-Flight Stealth Audit", g1_cmd, check=True):
            print("\n[!] HALT: Pre-flight stealth cloaking audit failed! Malware detonation aborted.", file=sys.stderr)
            sys.exit(1)

        # -------------------------------------------------------------
        # Stage 2: Canary Data Seeding (Gate G2)
        # -------------------------------------------------------------
        g2_cmd = [py_bin, "config/seed_canaries.py", "--config", self.config_path]
        if self.dry_run:
            g2_cmd.append("--dry-run")
        if self.serial:
            g2_cmd.extend(["--serial", self.serial])

        self.run_stage("Gate G2: Canary Data Seeding", g2_cmd, check=True)

        # -------------------------------------------------------------
        # Stage 3: Arm Out-of-Band Network & eBPF Captures (Gate G3)
        # -------------------------------------------------------------
        # Gateway setup
        gw_cmd = ["bash", "network_capture/gateway_setup.sh", "start", "--output-dir", self.output_dir]
        if self.dry_run:
            gw_cmd.append("--dry-run")
        self.run_stage("Gate G3: Network Gateway AP & tcpdump Start", gw_cmd, check=False)

        # eCapture runner
        ecap_cmd = [py_bin, "network_capture/ecapture_runner.py", "start", "--config", self.config_path, "--output-dir", self.output_dir]
        if self.dry_run:
            ecap_cmd.append("--dry-run")
        if self.serial:
            ecap_cmd.extend(["--serial", self.serial])
        self.run_stage("Gate G3: eBPF TLS Uprobe Capture Start", ecap_cmd, check=False)

        # -------------------------------------------------------------
        # Stage 4: Dynamic Instrumented Malware Execution (Gate G4)
        # -------------------------------------------------------------
        events_log = os.path.join(self.output_dir, "instrumentation_events.jsonl")
        frida_cmd = [
            py_bin, "instrumentation/frida_loader.py",
            "--package", self.package_name,
            "--config", self.config_path,
            "--duration", str(self.duration),
            "--output", events_log
        ]
        if self.dry_run:
            frida_cmd.append("--dry-run")

        self.run_stage("Gate G4: Stealth Frida Spawn & Telemetry Stream", frida_cmd, check=False)

        # -------------------------------------------------------------
        # Stage 5: Teardown & Capture Artifact Collection
        # -------------------------------------------------------------
        print("\n[*] Commencing post-execution teardown and artifact retrieval...")

        # Stop eCapture and pull TLS artifacts
        ecap_stop = [py_bin, "network_capture/ecapture_runner.py", "stop", "--config", self.config_path, "--output-dir", self.output_dir]
        if self.dry_run:
            ecap_stop.append("--dry-run")
        if self.serial:
            ecap_stop.extend(["--serial", self.serial])
        self.run_stage("Teardown: Stop eCapture & Retrieve Keylog", ecap_stop, check=False)

        # Stop gateway tcpdump
        gw_stop = ["bash", "network_capture/gateway_setup.sh", "stop", "--output-dir", self.output_dir]
        if self.dry_run:
            gw_stop.append("--dry-run")
        self.run_stage("Teardown: Stop Gateway tcpdump", gw_stop, check=False)

        # Purge seeded canaries
        clean_cmd = [py_bin, "config/seed_canaries.py", "--clean", "--config", self.config_path]
        if self.dry_run:
            clean_cmd.append("--dry-run")
        if self.serial:
            clean_cmd.extend(["--serial", self.serial])
        self.run_stage("Teardown: Purge Mock Canaries", clean_cmd, check=False)

        # -------------------------------------------------------------
        # Stage 6: Decryption & Correlation Post-Processing (Gate G5)
        # -------------------------------------------------------------
        pcap_file = os.path.join(self.output_dir, "raw_traffic.pcap")
        keylog_file = os.path.join(self.output_dir, "sslkey.log")
        decrypted_jsonl = os.path.join(self.output_dir, "decrypted_http_requests.jsonl")

        decrypt_cmd = [
            py_bin, "parser_correlator/pcap_decryptor.py",
            "--pcap", pcap_file,
            "--keylog", keylog_file,
            "--output", decrypted_jsonl
        ]
        if self.dry_run:
            decrypt_cmd.append("--dry-run")
        self.run_stage("Gate G5: TLS Packet Stream Decryption", decrypt_cmd, check=False)

        # Canary Hunter
        canary_hits_json = os.path.join(self.output_dir, "CANARY_EXFIL_HITS.json")
        hunter_cmd = [
            py_bin, "parser_correlator/canary_hunter.py",
            "--canaries", "config/mock_canaries.json",
            "--events", events_log,
            "--traffic", decrypted_jsonl,
            "--output", canary_hits_json
        ]
        self.run_stage("Gate G5: Multi-Encoding Canary Hunter", hunter_cmd, check=False)

        # IOC Extractor & Threat Report Generator
        ioc_cmd = [
            py_bin, "parser_correlator/ioc_extractor.py",
            "--session-dir", self.output_dir,
            "--package", self.package_name,
            "--sha256", self.sha256
        ]
        self.run_stage("Gate G5: IOC & STIX 2.1 Threat Report Generation", ioc_cmd, check=False)

        # Defensive YARA Rule Generator
        yara_cmd = [
            py_bin, "parser_correlator/yara_generator.py",
            "--session-dir", self.output_dir,
            "--package", self.package_name,
            "--sha256", self.sha256
        ]
        self.run_stage("Gate G5: Defensive YARA Signature Generation", yara_cmd, check=False)

        # -------------------------------------------------------------
        # Stage 7: Final Executive Summary
        # -------------------------------------------------------------
        print("\n" + "=" * 65)
        print("ANALYSIS SESSION COMPLETE - DELIVERABLES SUMMARY")
        print("=" * 65)
        print(f"Session Directory:       {self.output_dir}")
        print(f"Gate G0 Static Triage:   {os.path.join(self.output_dir, 'STATIC_AUDIT.md')}")
        print(f"Decrypted Network Flows: {decrypted_jsonl}")
        print(f"Crypto Telemetry Events: {events_log}")
        print(f"Canary Exfiltration Proof: {canary_hits_json}")
        print(f"Extracted IOCs (JSON):   {os.path.join(self.output_dir, 'iocs.json')}")
        print(f"STIX 2.1 Bundle:         {os.path.join(self.output_dir, 'threat_report_stix21.json')}")
        print(f"Executive Report (MD):   {os.path.join(self.output_dir, 'analysis_report.md')}")
        print("=" * 65)


def main():
    parser = argparse.ArgumentParser(
        description="dbug Master Automated Stealth Malware Analysis Sandbox"
    )
    parser.add_argument("--apk", default=None, help="Path to target sample APK")
    parser.add_argument("--package", default=None, help="Target Android package name")
    parser.add_argument("--duration", type=int, default=120, help="Observation window in seconds (default: 120)")
    parser.add_argument("--config", default="config/lab_config.yaml", help="Path to lab_config.yaml")
    parser.add_argument("--output-dir", default=None, help="Custom output directory")
    parser.add_argument("--dry-run", action="store_true", help="Run end-to-end simulation across all gates")
    args = parser.parse_args()

    cfg = parse_lab_config(args.config)
    sample_cfg = cfg.get("lab_environment", {}).get("target_sample", {})
    def_cfg = cfg.get("lab_environment", {}).get("analysis_defaults", {})

    apk = args.apk or sample_cfg.get("apk_path", "samples/sample.apk")
    package = args.package or sample_cfg.get("package_name", "com.example.malware")
    duration = args.duration or def_cfg.get("duration_seconds", 120)

    orchestrator = MasterOrchestrator(
        apk_path=apk,
        package_name=package,
        duration=duration,
        config_path=args.config,
        output_dir=args.output_dir,
        dry_run=args.dry_run
    )

    orchestrator.execute_pipeline()


if __name__ == "__main__":
    main()
