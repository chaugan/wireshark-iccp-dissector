#!/usr/bin/env bash
# Show per-conformance-block coverage from the test PCAP.
set -euo pipefail
PCAP=/mnt/c/Users/chris/OneDrive/Documents/Programming/wireshark_iccp/pcaps/generated/iccp-phase1.pcap

echo "=== packets grouped by conformance block ==="
tshark -r "$PCAP" -d tcp.port==10102,tpkt \
    -Y 'iccp.cb' \
    -T fields -e iccp.cb -e iccp.object.category \
    2>/dev/null | sort -u

echo
echo "=== per-block packet counts ==="
tshark -r "$PCAP" -d tcp.port==10102,tpkt \
    -Y 'iccp.cb' \
    -T fields -e iccp.cb \
    2>/dev/null | sort | uniq -c | sort -rn

echo
echo "=== unique ICCP operations observed ==="
tshark -r "$PCAP" -d tcp.port==10102,tpkt \
    -Y 'iccp.operation' \
    -T fields -e iccp.operation \
    2>/dev/null | sort | uniq -c | sort -rn

echo
echo "=== expert-info counts ==="
tshark -r "$PCAP" -d tcp.port==10102,tpkt -V 2>/dev/null \
    | grep -E 'Expert Info .*(ICCP|iccp)' \
    | sort | uniq -c | sort -rn
