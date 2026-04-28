#!/usr/bin/env bash
set -euo pipefail
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
INP=/tmp/iccp-wash-input.pcap
OUT=/tmp/iccp-wash-numeric.pcap

# regenerate input
editcap -F pcap "$REPO/pcaps/generated/iccp-phase1.pcap" "$INP" >/dev/null

python3 "$REPO/scripts/wash-pcap.py" "$INP" "$OUT" --scrub-numeric 2>&1

echo
echo "--- MMS still dispatches? ---"
tshark -r "$OUT" -d tcp.port==10102,tpkt -T fields -e frame.protocols 2>/dev/null | sort -u

echo
echo "--- iccp.object.name (should still be hashed names) ---"
tshark -r "$OUT" -d tcp.port==10102,tpkt -Y 'iccp.object.name' -T fields -e iccp.object.name 2>/dev/null | sort -u | head -8

echo
echo "--- iccp.report.point_count count ---"
tshark -r "$OUT" -d tcp.port==10102,tpkt -Y 'iccp.report.point_count' -T fields -e frame.number -e iccp.report.point_count 2>/dev/null | head -5
