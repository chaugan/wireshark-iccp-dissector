#!/usr/bin/env bash
# Regression tests for the ICCP/TASE.2 Wireshark plugin.
# Runs tshark against the generated test PCAP and verifies key fields,
# categories, operations, and expert-infos appear as expected. Exits
# non-zero on any mismatch, suitable for CI.

set -euo pipefail

PCAP=/mnt/c/Users/chris/OneDrive/Documents/Programming/wireshark_iccp/pcaps/generated/iccp-phase1.pcap
DECODE=(-d tcp.port==10102,tpkt)

if [[ ! -f $PCAP ]]; then
    echo "FAIL: test PCAP not present at $PCAP" >&2
    echo "      run scripts/gen-pcap.sh first" >&2
    exit 2
fi

fails=0
pass() { printf "  \033[32mPASS\033[0m %s\n" "$1"; }
fail() { printf "  \033[31mFAIL\033[0m %s\n" "$1"; fails=$((fails + 1)); }

# Helper: assert a given display filter matches at least one packet.
assert_has() {
    local name=$1; local filt=$2
    local n
    n=$(tshark -r "$PCAP" "${DECODE[@]}" -Y "$filt" 2>/dev/null | wc -l)
    if [[ $n -gt 0 ]]; then pass "$name ($n packets)"
    else                    fail "$name [filter: $filt]"
    fi
}

# Helper: assert a given display filter matches *exactly* N packets.
assert_count() {
    local name=$1; local filt=$2; local want=$3
    local n
    n=$(tshark -r "$PCAP" "${DECODE[@]}" -Y "$filt" 2>/dev/null | wc -l)
    if [[ $n -eq $want ]]; then pass "$name ($n packets)"
    else                        fail "$name: got $n, want $want [filter: $filt]"
    fi
}

# Helper: assert a `-T fields` output contains a given substring.
assert_field_has() {
    local name=$1; local filt=$2; local field=$3; local want=$4
    local out
    out=$(tshark -r "$PCAP" "${DECODE[@]}" -Y "$filt" -T fields -e "$field" 2>/dev/null | sort -u)
    if grep -qF -- "$want" <<< "$out"; then pass "$name ($field contains \"$want\")"
    else                                    fail "$name: $field did not contain \"$want\"\n        got: $out"
    fi
}

echo "== plugin load =="
if tshark -G plugins 2>&1 | grep -q iccp; then pass "iccp plugin loaded"
else fail "iccp plugin not found in tshark -G plugins"; exit 1; fi

echo
echo "== Phase 1: association and naming =="
assert_has "iccp protocol present"                  'iccp'
assert_has "association state recorded"             'iccp.association.state'
assert_has "at least one Confirmed ICCP assoc"      'iccp.association.state == "Confirmed ICCP"'
assert_has "Bilateral_Table matched"                'iccp.object.name contains "Bilateral_Table"'

echo
echo "== Phase 2: operation classification =="
assert_has "Associate-Request detected"             'iccp.operation == "Associate-Request"'
assert_has "Associate-Response detected"            'iccp.operation == "Associate-Response"'
assert_has "Read-Request detected"                  'iccp.operation == "Read-Request"'
assert_has "Read-Response detected"                 'iccp.operation == "Read-Response"'

echo
echo "== Phase 2/4: all 9 conformance blocks =="
for cb in 1 2 3 4 5 6 7 8 9; do
    assert_has "Conformance Block $cb seen" "iccp.cb == $cb"
done

echo
echo "== Phase 3: Device Control (Block 5) =="
assert_field_has "SBOSelect classified" \
    'iccp.object.name contains "SBOSelect"' 'iccp.object.category' 'Device Select-Before-Operate'
assert_field_has "SBOOperate classified" \
    'iccp.object.name contains "SBOOperate"' 'iccp.object.category' 'Device SBO Operate'
assert_field_has "TagOperate classified as Tag, not Direct" \
    'iccp.object.name contains "TagOperate"' 'iccp.object.category' 'Device Tag Operate'
assert_has "Device state recorded"                  'iccp.device.state'
assert_has "SBO violation raised somewhere"         '_ws.expert.message contains "SBO violation"'
assert_has "Direct Operate warning raised"          '_ws.expert.message contains "physical device action"'

echo
echo "== False-positive guard: plain MMS (IEC 61850-only) not confirmed =="
# Association 1 is mms_utility -i (identify). It has Initiate PDUs but no
# ICCP-reserved names. Frames 4..14. Verify none of those packets are
# Confirmed ICCP.
assert_count "associations 1 + 2 never confirm ICCP" \
    'frame.number <= 35 and iccp.association.state == "Confirmed ICCP"' 0

echo
if [[ $fails -eq 0 ]]; then
    echo "=== all checks passed ==="
    exit 0
else
    echo "=== $fails check(s) failed ==="
    exit 1
fi
