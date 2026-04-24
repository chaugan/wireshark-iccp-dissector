#!/usr/bin/env bash
# Show every mms.* field that shows up in a Read-Response frame.
set -euo pipefail
PCAP=/mnt/c/Users/chris/OneDrive/Documents/Programming/wireshark_iccp/pcaps/generated/iccp-phase1.pcap
FRAME=${1:-55}
tshark -r "$PCAP" -d tcp.port==10102,tpkt -V -Y "frame.number==$FRAME" 2>/dev/null \
  | awk '/confirmed-ResponsePDU/,/Inter-Control/' \
  | head -n 30
echo '---'
echo 'present mms.* abbrevs in this frame:'
tshark -r "$PCAP" -d tcp.port==10102,tpkt -Y "frame.number==$FRAME" \
    -T fields -e mms.success_element -e mms.failure_element -e mms.failure \
    -e mms.AccessResult -e mms.success -e mms.Data -e mms.data_element 2>/dev/null
