#!/usr/bin/env bash
set -euo pipefail
PCAP=${1:-/mnt/c/Users/chris/OneDrive/Documents/Programming/wireshark_iccp/pcaps/generated/iccp-phase1.pcap}
NUM=${2:-1}
tshark -r "$PCAP" -V -Y "frame.number == $NUM" 2>/dev/null
