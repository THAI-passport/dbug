#!/usr/bin/env bash
#
# scripts/install_dependencies.sh: Bootstrap Python dependencies for dbug.
#
# Installs core + defensive emulation packages from requirements.txt and verifies
# that every required module imports cleanly, with a Frida version floor check
# (>= 16.0.0) because Gate G4 dynamic instrumentation requires a modern Frida.
#
# Usage:
#   ./scripts/install_dependencies.sh               # install from requirements.txt
#   DBUG_TRUST_PYPI=1 ./scripts/install_dependencies.sh  # add --trusted-host for PyPI
#
set -euo pipefail

REQUIREMENTS="${1:-requirements.txt}"
PY_BIN="${PYTHON_BIN:-python3}"

echo "[*] dbug dependency bootstrap"
echo "    Python: $($PY_BIN --version)"
echo "    Requirements: $REQUIREMENTS"

if [[ ! -f "$REQUIREMENTS" ]]; then
    echo "[!] Requirements file not found: $REQUIREMENTS" >&2
    exit 1
fi

# Some egress proxies intercept PyPI TLS certificate verification. Opt in with
# DBUG_TRUST_PYPI=1 to add --trusted-host for pypi.org / files.pythonhosted.org.
TRUSTED_HOST_ARGS=""
if [[ "${DBUG_TRUST_PYPI:-0}" == "1" ]]; then
    TRUSTED_HOST_ARGS="--trusted-host pypi.org --trusted-host files.pythonhosted.org"
    echo "[*] DBUG_TRUST_PYPI=1: adding --trusted-host for PyPI mirrors"
fi

echo "[*] Installing Python dependencies from $REQUIREMENTS ..."
$PY_BIN -m pip install --upgrade pip $TRUSTED_HOST_ARGS >/dev/null 2>&1 || true
$PY_BIN -m pip install -r "$REQUIREMENTS" $TRUSTED_HOST_ARGS

echo "[*] Verifying core module imports ..."
$PY_BIN - <<'PY'
import importlib
import sys

mods = ["frida", "yaml", "elftools", "unicorn", "capstone"]
failed = []
for m in mods:
    try:
        mod = importlib.import_module(m)
        ver = getattr(mod, "__version__", "n/a")
        print(f"    [OK] {m} {ver}")
    except ImportError as e:
        print(f"    [FAIL] {m}: {e}")
        failed.append(m)

if failed:
    print(f"[!] Missing required modules: {', '.join(failed)}", file=sys.stderr)
    sys.exit(1)
PY

echo "[*] Validating Frida version floor (>= 16.0.0) ..."
$PY_BIN - <<'PY'
import sys

import frida


def ver_tuple(v):
    return tuple(int(x) for x in str(v).split(".") if x.isdigit())


got = frida.__version__
min_ver = "16.0.0"
if ver_tuple(got) < ver_tuple(min_ver):
    print(f"[!] Frida {got} is below required minimum {min_ver}", file=sys.stderr)
    sys.exit(1)
print(f"    [OK] frida {got} >= {min_ver}")
PY

echo "[+] Dependencies installed and verified."
