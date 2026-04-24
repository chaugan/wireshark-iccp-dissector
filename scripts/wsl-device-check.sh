#!/usr/bin/env bash
# Inspect the Block-5 device control packets in the test PCAP.
set -euo pipefail
PCAP=/mnt/c/Users/chris/OneDrive/Documents/Programming/wireshark_iccp/pcaps/generated/iccp-phase1.pcap

echo "=== device-categorised packets ==="
tshark -r "$PCAP" -d tcp.port==10102,tpkt -Y 'iccp.cb == 5' \
    -T fields \
    -e frame.number \
    -e iccp.operation \
    -e iccp.object.category \
    -e iccp.object.name \
    -e iccp.device.state \
    2>/dev/null

echo
echo "=== expert-info entries on device packets ==="
tshark -r "$PCAP" -d tcp.port==10102,tpkt -Y 'iccp.cb == 5' -V 2>/dev/null \
    | grep -E 'iccp\.(device|object)|Device.*Operate|SBO violation|physical' \
    | head -n 40
