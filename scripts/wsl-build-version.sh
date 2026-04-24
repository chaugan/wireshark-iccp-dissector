#!/usr/bin/env bash
# wsl-build-version.sh <release-branch>
#
# End-to-end: clone Wireshark source at the given release branch,
# build libs + tshark (no Qt GUI), install to a version-specific
# prefix under ~/ws-install-<ver>, build the iccp plugin against it,
# and copy the resulting iccp.so into the repo's out/ dir named by
# version. Idempotent: reuses existing clones and install trees.
#
# Usage:
#   bash scripts/wsl-build-version.sh release-4.2
#   bash scripts/wsl-build-version.sh release-4.4
#   bash scripts/wsl-build-version.sh release-4.6

set -euo pipefail

BRANCH=${1:?usage: $0 <release-branch, e.g. release-4.4>}
VER=${BRANCH#release-}

REPO=/mnt/c/Users/chris/OneDrive/Documents/Programming/wireshark_iccp
SRC=$HOME/ws-src-$VER
BLD=$HOME/ws-build-$VER
INS=$HOME/ws-install-$VER
PLUGIN_BLD=$HOME/iccp-build-$VER
OUTDIR=$REPO/out

mkdir -p "$OUTDIR"

echo "==================================="
echo "Wireshark $VER build pipeline"
echo "  source:  $SRC"
echo "  build:   $BLD"
echo "  install: $INS"
echo "==================================="

# 1. Clone
if [[ ! -d $SRC/.git ]]; then
    echo "== clone $BRANCH =="
    git clone --depth 1 --branch "$BRANCH" https://github.com/wireshark/wireshark.git "$SRC"
fi

# 2. Configure Wireshark (libs + tshark, no Qt GUI)
if [[ ! -f $BLD/CMakeCache.txt ]]; then
    echo "== cmake configure =="
    mkdir -p "$BLD"
    cmake -S "$SRC" -B "$BLD" \
        -DBUILD_wireshark=OFF \
        -DBUILD_logwolf=OFF \
        -DBUILD_rawshark=OFF \
        -DBUILD_randpkt=OFF \
        -DBUILD_dftest=OFF \
        -DBUILD_sharkd=OFF \
        -DBUILD_androiddump=OFF \
        -DBUILD_sshdump=OFF \
        -DBUILD_ciscodump=OFF \
        -DBUILD_udpdump=OFF \
        -DBUILD_wifidump=OFF \
        -DBUILD_dpauxmon=OFF \
        -DBUILD_randpktdump=OFF \
        -DBUILD_etwdump=OFF \
        -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_INSTALL_PREFIX="$INS"
fi

# 3. Build (everything the configure enabled -- CMake install manifest
# expects all configured targets to be present, so don't target-filter).
echo "== build =="
cmake --build "$BLD" -j"$(nproc)" 2>&1 | tail -5

# 4. Install (default + Development components)
echo "== install =="
cmake --install "$BLD" --prefix "$INS"                          2>&1 | tail -5
cmake --install "$BLD" --prefix "$INS" --component Development 2>&1 | tail -5

# Sanity: WiresharkConfig.cmake must exist in the install tree.
WSCFG=$(find "$INS" -name WiresharkConfig.cmake | head -1)
if [[ -z $WSCFG ]]; then
    echo "ERROR: WiresharkConfig.cmake not produced under $INS" >&2
    exit 1
fi
echo "WiresharkConfig: $WSCFG"
WSDIR=$(dirname "$WSCFG")

# 5. Build our plugin against this install
echo "== plugin =="
mkdir -p "$PLUGIN_BLD"
cmake -S "$REPO" -B "$PLUGIN_BLD" -DWireshark_DIR="$WSDIR" >/dev/null 2>&1
cmake --build "$PLUGIN_BLD" -j"$(nproc)" 2>&1 | tail -5

# 6. Copy artifact
SO=$PLUGIN_BLD/iccp.so
if [[ ! -f $SO ]]; then
    echo "ERROR: iccp.so not built" >&2
    exit 1
fi
DEST=$OUTDIR/iccp-linux-x86_64-wireshark-$VER.so
cp "$SO" "$DEST"
echo "==> $DEST ($(stat -c %s "$DEST") bytes)"
