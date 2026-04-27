#!/usr/bin/env bash
# Build the iccp plugin for every Wireshark minor we care about, against
# the cached WSL install trees produced by wsl-build-version.sh. Drops the
# resulting .so files into release/v<TAG>/, named per the v0.2.0 convention.
#
# Usage: bash scripts/wsl-build-all-versions.sh <tag>
#   e.g. bash scripts/wsl-build-all-versions.sh v0.3.0

set -euo pipefail
TAG=${1:?usage: $0 <tag, e.g. v0.3.0>}

REPO=/mnt/c/Users/chris/OneDrive/Documents/Programming/wireshark_iccp
DEST_DIR=$REPO/release/$TAG
mkdir -p "$DEST_DIR"

for VER in 4.2 4.4 4.6; do
    INS=$HOME/ws-install-$VER
    BLD=$HOME/iccp-build-$VER
    WSDIR=$INS/lib/cmake/wireshark
    if [[ ! -f "$WSDIR/WiresharkConfig.cmake" ]]; then
        echo "ERROR: $WSDIR/WiresharkConfig.cmake not found" >&2
        echo "Run scripts/wsl-build-version.sh release-$VER first." >&2
        exit 1
    fi
    echo "=== plugin for $VER (Wireshark_DIR=$WSDIR) ==="
    rm -rf "$BLD"
    mkdir -p "$BLD"
    cmake -S "$REPO" -B "$BLD" -DWireshark_DIR="$WSDIR" >/dev/null
    cmake --build "$BLD" -j"$(nproc)" 2>&1 | tail -3
    DEST=$DEST_DIR/iccp-$TAG-linux-x86_64-wireshark-$VER.so
    cp "$BLD/iccp.so" "$DEST"
    ls -la "$DEST"
done
