#!/usr/bin/env bash
# Audit the output of scripts/wash-pcap.py: scan the washed pcap for
# any leak of sensitive substrings we expect the washer to hide.
# Prints counts side-by-side (original vs washed) for every known
# substring pattern, then dumps every >=8-char printable-ASCII token
# in the washed file so a human can spot-check anything the automated
# list didn't anticipate.

set -euo pipefail
bash "$(dirname "$0")/../tests/test-washer.sh" >/dev/null 2>&1 || true
IN=/tmp/iccp-wash-input.pcap
OUT=/tmp/iccp-wash-output.pcap
ls -la "$IN" "$OUT"
echo
echo "== byte-grep for sensitive substrings =="
for s in TestDomain Bilateral Transfer_Set DSConditions Device_Breaker Device_Line Event_Condition Account_Operator Supported_Features VAR_ 127.0.0.1 lo0 localhost Information_Message Program_PCS Error_Log DSTimeSeries; do
    orig=$(LC_ALL=C grep -aco "$s" "$IN" 2>/dev/null || true)
    washed=$(LC_ALL=C grep -aco "$s" "$OUT" 2>/dev/null || true)
    printf "  %-24s  original=%3s  washed=%3s\n" "$s" "${orig:-0}" "${washed:-0}"
done
echo
echo "== printable-ASCII strings >= 8 chars in the WASHED file =="
strings -n 8 "$OUT" | sort -u
echo
echo "== same in the ORIGINAL file, for side-by-side comparison =="
strings -n 8 "$IN" | sort -u
