#!/usr/bin/env bash
# Dump all MMS hf fields registered by Wireshark's MMS dissector.
# Output columns: abbrev ftype base
set -euo pipefail
# tshark -G fields columns: F  Name  Abbrev  Type  Parent  Blurb  Base  Bitmask
# We want fields whose Parent is the mms protocol.
tshark -G fields 2>/dev/null | awk -F'\t' '$5 == "mms" { print $3 "\t" $4 }'
