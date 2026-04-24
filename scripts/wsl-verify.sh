#!/usr/bin/env bash
# Install the built plugin and sanity-check Wireshark loads it.
set -euo pipefail

BLD="$HOME/build/wireshark_iccp"
DST="$HOME/.local/lib/wireshark/plugins/4.2/epan"
mkdir -p "$DST"
cp "$BLD/iccp.so" "$DST/"

echo "--- tshark plugins ---"
tshark -G plugins 2>&1 | grep -i iccp || echo "(no iccp plugin line)"

echo
echo "--- tshark protocols ---"
tshark -G protocols 2>&1 | grep -i iccp || echo "(no iccp protocol line)"

echo
echo "--- tshark iccp fields ---"
tshark -G fields 2>/dev/null | awk -F'\t' '$5 == "iccp" { print $3, "  " $4 }'

echo
echo "--- smoke (no args, should not crash) ---"
tshark -v 2>&1 | head -n 2
