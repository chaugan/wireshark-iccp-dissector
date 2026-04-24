#!/usr/bin/env bash
set -euo pipefail
tshark -G fields 2>/dev/null \
  | awk -F'\t' '$5 == "mms" { print $3 "\t" $4 }' \
  | grep -iE 'data|real|float|binary|visible|octet|structure|accessResult|success|failure|listOf'
