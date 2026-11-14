#!/usr/bin/env bash
# Create the private Python environment the ghidra_angr_emulate MCP tool runs angr in.
#
# angr pins exact versions of a large dependency tree, so installing it into a shared Python
# tends to break either angr or whatever else lives there. This creates a virtual environment
# used for nothing else, installs angr into it, checks that it imports, and records the
# interpreter in ~/.decompfuncutils/angr-python, which is where the Ghidra extension looks.
# A running Ghidra picks it up on the next tool call - no restart.
#
# Usage: tools/setup-angr.sh [venv-path] [--upgrade]
#   venv-path defaults to ~/.decompfuncutils/angr-venv (needs roughly 450 MB)
#   PYTHON=/path/to/python3 selects the interpreter used to create it (3.10 or newer)
set -euo pipefail

VENV="${HOME}/.decompfuncutils/angr-venv"
UPGRADE=0
for arg in "$@"; do
    case "$arg" in
        --upgrade) UPGRADE=1 ;;
        *) VENV="$arg" ;;
    esac
done
PYTHON="${PYTHON:-python3}"
VENV_PYTHON="${VENV}/bin/python3"

if [ ! -x "$VENV_PYTHON" ]; then
    echo "==> Creating virtual environment in $VENV"
    "$PYTHON" -m venv "$VENV"
fi

if [ "$UPGRADE" = 1 ] || ! "$VENV_PYTHON" -c "import angr" >/dev/null 2>&1; then
    echo "==> Installing angr (a few hundred MB, this takes a few minutes)"
    if [ "$UPGRADE" = 1 ]; then
        "$VENV_PYTHON" -m pip install --disable-pip-version-check --no-cache-dir --upgrade angr
    else
        "$VENV_PYTHON" -m pip install --disable-pip-version-check --no-cache-dir angr
    fi
fi

VERSION="$("$VENV_PYTHON" -c "import angr; print(angr.__version__)" 2>/dev/null)" || {
    echo "angr was installed but does not import. Run: $VENV_PYTHON -c 'import angr'" >&2
    exit 1
}

mkdir -p "${HOME}/.decompfuncutils"
printf '%s' "$(cd "$(dirname "$VENV_PYTHON")" && pwd)/python3" > "${HOME}/.decompfuncutils/angr-python"

echo "==> angr ${VERSION} is ready"
echo "    interpreter: ${VENV_PYTHON}"
echo "    recorded in: ${HOME}/.decompfuncutils/angr-python"
