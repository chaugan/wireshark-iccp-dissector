#!/usr/bin/env bash
# Dump every hf-field registered under the MMS protocol.
#   Column 1: abbrev (e.g. mms.itemId)
#   Column 2: ftype   (e.g. FT_STRING)
# Run with optional regex arg to filter:
#   bash dump-mms-fields.sh 'data|real'
set -euo pipefail
pat=${1:-}
tshark -G fields 2>/dev/null \
  | awk -F'\t' '$5 == "mms" { print $3 "\t" $4 }' \
  | { if [[ -n $pat ]]; then grep -iE "$pat"; else cat; fi; }
