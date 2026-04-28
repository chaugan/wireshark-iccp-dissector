#!/usr/bin/env bash
# Configure + build the ICCP plugin inside WSL Ubuntu.
# Source tree resolved from this script's location; build tree under $HOME
# to avoid OneDrive sync churn when the source is on a /mnt/c clone.

set -euo pipefail

SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BLD="$HOME/build/wireshark-iccp-dissector"

mkdir -p "$BLD"
cd "$BLD"

if [[ ! -f Makefile && ! -f build.ninja ]]; then
    echo "== cmake configure =="
    cmake "$SRC"
fi

echo "== build =="
cmake --build . -- -j"$(nproc)"

echo "== artifacts =="
ls -la iccp.so 2>/dev/null || ls -la *.so 2>/dev/null || true
