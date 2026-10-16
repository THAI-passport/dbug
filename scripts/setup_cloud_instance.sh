#!/usr/bin/env bash
#
# setup_cloud_instance.sh: Automated Provisioning Script for Cloud Instances & Headless Hosts.
#
# Configures a cloud virtual machine (AWS EC2, Google Cloud Compute, DigitalOcean Droplet,
# Ubuntu/Debian VPS) for zero-phone Android dynamic analysis and native executable debugging.
#
# Usage:
#   bash scripts/setup_cloud_instance.sh
#
set -euo pipefail

echo "================================================================="
echo "dbug CLOUD INSTANCE AUTOMATED PROVISIONING"
echo "================================================================="

# 1. Detect OS Distribution
if [[ -f /etc/os-release ]]; then
    . /etc/os-release
    OS_NAME="$ID"
    OS_VERSION="$VERSION_ID"
    echo "[*] Detected Operating System: $NAME $VERSION_ID"
else
    OS_NAME="unknown"
    echo "[!] Warning: Unable to detect OS distribution from /etc/os-release."
fi

# 2. Update package repositories and install system packages
if [[ "$OS_NAME" =~ ^(ubuntu|debian)$ ]]; then
    echo "[*] Updating apt package indices..."
    if command -v sudo >/dev/null 2>&1; then
        SUDO="sudo"
    else
        SUDO=""
    fi

    $SUDO apt-get update -y
    echo "[*] Installing system dependencies, QEMU user emulation, and network tools..."
    $SUDO apt-get install -y --no-install-recommends \
        python3 \
        python3-pip \
        python3-dev \
        build-essential \
        git \
        curl \
        wget \
        ca-certificates \
        android-tools-adb \
        qemu-user-static \
        tcpdump \
        tshark \
        iproute2 \
        iptables \
        procps
else
    echo "[-] Non-Debian/Ubuntu host detected. Ensure Python 3, ADB, QEMU, and tshark are installed."
fi

# 3. Check for Virtualization / KVM Support (Optional Redroid acceleration)
echo "[*] Checking hardware virtualization support..."
if [[ -e /dev/kvm ]]; then
    echo "    [+] /dev/kvm is AVAILABLE. Containerized Android (Redroid) hardware acceleration enabled."
else
    echo "    [-] /dev/kvm NOT detected. dbug will run in Cloud/Virtual Sandbox Mode (CPU emulation)."
fi

# 4. Bootstrap Python Dependencies
echo "[*] Installing Python dependencies from requirements.txt..."
PY_BIN="${PYTHON_BIN:-python3}"
$PY_BIN -m pip install --upgrade pip >/dev/null 2>&1 || true
$PY_BIN -m pip install -r requirements.txt

# 5. Build Default Defensive Mock Samples
echo "[*] Building defensive mock test samples..."
$PY_BIN samples/build_samples.py

# 6. Verify dbug Installation & Run Out-Of-The-Box Self-Test
echo "[*] Running dbug out-of-the-box self-test..."
$PY_BIN orchestrator.py --mode virtual --profile all --duration 1

echo "================================================================="
echo "[+] CLOUD INSTANCE PROVISIONING COMPLETE"
echo "================================================================="
echo "dbug is ready for zero-phone Android dynamic analysis and executable debugging."
echo ""
echo "Quickstart Commands:"
echo "  1. Analyze default sample:     python3 orchestrator.py"
echo "  2. Analyze Android APK:        python3 orchestrator.py --apk path/to/app.apk --profile all"
echo "  3. Debug native ELF binary:    python3 orchestrator.py --binary path/to/binary.elf --profile malware"
echo "  4. Run interactive session:    python3 orchestrator.py --apk path/to/app.apk --interactive"
echo "================================================================="
