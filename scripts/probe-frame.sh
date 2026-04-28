#!/usr/bin/env bash
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PCAP="${PCAP:-$REPO_ROOT/pcaps/generated/iccp-phase1.pcap}"
FRAME=${1:-38}

echo "=== frame $FRAME, selected fields ==="
tshark -r "$PCAP" -d tcp.port==10102,tpkt -Y "frame.number==$FRAME" \
    -T fields \
    -e mms.itemId \
    -e mms.domainId \
    -e mms.Identifier \
    -e mms.vmd_specific \
    -e mms.newIdentifier \
    -e mms.initiate_RequestPDU_element \
    -e mms.initiate_ResponsePDU_element \
    2>/dev/null

echo
echo "=== frame $FRAME, verbose PDU header ==="
tshark -r "$PCAP" -d tcp.port==10102,tpkt -Y "frame.number==$FRAME" -V 2>/dev/null \
    | grep -E 'initiate|confirmed|Request|Response|MMSpdu' | head -n 10

echo
echo "=== frame $FRAME, grep lines with identifier-ish names ==="
tshark -r "$PCAP" -d tcp.port==10102,tpkt -Y "frame.number==$FRAME" -V 2>/dev/null \
    | grep -E 'itemId|domainId|Identifier|vmd_specific|newIdentifier|VisibleString'
