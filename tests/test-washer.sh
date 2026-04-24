#!/usr/bin/env bash
# Smoke-test scripts/wash-pcap.py: wash our own generated PCAP and
# verify (1) the packet count is preserved, (2) IPs / MACs / MMS
# identifiers are rewritten, (3) the protocol stack still dispatches
# to MMS, (4) preserved names (Bilateral_Table_ID) pass through.

set -euo pipefail

REPO=$(cd "$(dirname "$0")/.." && pwd)
SRC_NG=$REPO/pcaps/generated/iccp-phase1.pcap
SRC_PCAP=/tmp/iccp-wash-input.pcap
OUT_PCAP=/tmp/iccp-wash-output.pcap

fails=0
pass() { printf "  \033[32mPASS\033[0m %s\n" "$1"; }
fail() { printf "  \033[31mFAIL\033[0m %s\n" "$1"; fails=$((fails + 1)); }

# need an Ethernet-linktype pcap; convert from pcapng
editcap -F pcap "$SRC_NG" "$SRC_PCAP" >/dev/null

python3 "$REPO/scripts/wash-pcap.py" "$SRC_PCAP" "$OUT_PCAP" >/tmp/wash-stderr 2>&1
cat /tmp/wash-stderr

orig_pkts=$(tshark -r "$SRC_PCAP" -T fields -e frame.number 2>/dev/null | wc -l)
washed_pkts=$(tshark -r "$OUT_PCAP" -T fields -e frame.number 2>/dev/null | wc -l)

if [[ $orig_pkts -eq $washed_pkts ]]; then
    pass "packet count preserved ($orig_pkts)"
else
    fail "packet count drifted: orig=$orig_pkts washed=$washed_pkts"
fi

orig_ips=$(tshark -r "$SRC_PCAP" -T fields -e ip.src -e ip.dst 2>/dev/null | tr '\t' '\n' | sort -u | grep -v '^$' | head -5)
washed_ips=$(tshark -r "$OUT_PCAP" -T fields -e ip.src -e ip.dst 2>/dev/null | tr '\t' '\n' | sort -u | grep -v '^$' | head -5)

if grep -q '^192\.0\.2\.' <<< "$washed_ips"; then
    pass "IPs remapped to 192.0.2.x (RFC 5737)"
else
    fail "IPs not remapped. washed: $washed_ips"
fi

# did the domain get rewritten?
orig_domain=$(tshark -r "$SRC_PCAP" -d tcp.port==10102,tpkt -Y 'mms.domainId' -T fields -e mms.domainId 2>/dev/null | sort -u | head -1)
washed_domain=$(tshark -r "$OUT_PCAP" -d tcp.port==10102,tpkt -Y 'mms.domainId' -T fields -e mms.domainId 2>/dev/null | sort -u | head -1)

if [[ "$orig_domain" == "TestDomain" ]]; then
    pass "original pcap has 'TestDomain'"
    if [[ "$washed_domain" != "TestDomain" && -n "$washed_domain" ]]; then
        pass "washed pcap has rewritten domain ('$washed_domain')"
    else
        fail "washed domain unchanged ('$washed_domain')"
    fi
else
    fail "test pcap missing 'TestDomain'; got '$orig_domain'"
fi

# did preserved names pass through?
orig_bilat=$(tshark -r "$SRC_PCAP" -d tcp.port==10102,tpkt -Y 'mms.itemId' -T fields -e mms.itemId 2>/dev/null | grep -c 'Bilateral_Table_ID')
washed_bilat=$(tshark -r "$OUT_PCAP" -d tcp.port==10102,tpkt -Y 'mms.itemId' -T fields -e mms.itemId 2>/dev/null | grep -c 'Bilateral_Table_ID')

if [[ $orig_bilat -gt 0 && $washed_bilat -gt 0 ]]; then
    pass "'Bilateral_Table_ID' preserved (on DEFAULT_PRESERVED list)"
else
    fail "'Bilateral_Table_ID' pass-through failed (orig=$orig_bilat washed=$washed_bilat)"
fi

# MMS structure still valid?  Don't use grep -q here because early exit
# causes tshark to get SIGPIPE, which pipefail + set -e turns into a
# pipeline failure (see https://stackoverflow.com/q/22464786).
mms_frames=$(tshark -r "$OUT_PCAP" -d tcp.port==10102,tpkt -T fields -e frame.protocols 2>/dev/null | grep -c mms || true)
if [[ $mms_frames -gt 0 ]]; then
    pass "MMS dissection still works on washed capture ($mms_frames frames)"
else
    fail "washed capture no longer dispatches to MMS"
fi

echo
if [[ $fails -eq 0 ]]; then
    echo "=== washer tests: all passed ==="
    exit 0
else
    echo "=== washer tests: $fails failed ==="
    exit 1
fi
