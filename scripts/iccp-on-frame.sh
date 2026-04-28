#!/usr/bin/env bash
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PCAP="${PCAP:-$REPO_ROOT/pcaps/generated/iccp-phase1.pcap}"
FRAME=${1:-10}
tshark -r "$PCAP" -d tcp.port==10102,tpkt -V -Y "frame.number==$FRAME" 2>/dev/null \
    | awk '/^\[?Inter-Control Center/,0'
