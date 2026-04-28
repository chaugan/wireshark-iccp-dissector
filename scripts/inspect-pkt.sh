#!/usr/bin/env bash
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PCAP="${1:-$REPO_ROOT/pcaps/generated/iccp-phase1.pcap}"
NUM=${2:-1}
tshark -r "$PCAP" -V -Y "frame.number == $NUM" 2>/dev/null
