#!/usr/bin/env bash
# Configure + build the ICCP plugin inside WSL Ubuntu.
# Source tree lives on /mnt/c (Windows side); build tree under $HOME to
# avoid OneDrive sync churn.

set -euo pipefail

SRC=/mnt/c/Users/chris/OneDrive/Documents/Programming/wireshark_iccp
BLD="$HOME/build/wireshark_iccp"

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
