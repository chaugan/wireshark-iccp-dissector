#!/usr/bin/env bash
# Run the Phase 1 plugin against the generated PCAP and print results.
set -euo pipefail

PCAP=${1:-/mnt/c/Users/chris/OneDrive/Documents/Programming/wireshark_iccp/pcaps/generated/iccp-phase1.pcap}

if [[ ! -f $PCAP ]]; then
    echo "pcap not found: $PCAP" >&2
    exit 1
fi

# Port 10102 isn't the standard ISO-TSAP port (102), so tell tshark to
# dispatch the MMS stack for it.
DECODE=(-d tcp.port==10102,tpkt)

echo "=== protocol column distribution ==="
tshark -r "$PCAP" "${DECODE[@]}" -T fields -e _ws.col.Protocol 2>/dev/null \
    | sort | uniq -c | sort -rn

echo
echo "=== frame.protocols distribution ==="
tshark -r "$PCAP" "${DECODE[@]}" -T fields -e frame.protocols 2>/dev/null \
    | sort | uniq -c | sort -rn

echo
echo "=== iccp-tagged packets ==="
tshark -r "$PCAP" "${DECODE[@]}" -Y iccp 2>/dev/null | head -n 30

echo
echo "=== iccp fields per flagged packet ==="
tshark -r "$PCAP" "${DECODE[@]}" -Y iccp \
    -T fields \
    -e frame.number \
    -e iccp.association.state \
    -e iccp.operation \
    -e iccp.object.category \
    -e iccp.object.name \
    2>/dev/null
