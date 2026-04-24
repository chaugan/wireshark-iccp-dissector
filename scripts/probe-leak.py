#!/usr/bin/env python3
"""Dump hex + ASCII around every occurrence of a substring in a file."""
import sys
pat = sys.argv[1].encode()
data = open(sys.argv[2], 'rb').read()
i = 0
while True:
    j = data.find(pat, i)
    if j < 0: break
    s = max(0, j - 8)
    e = j + len(pat) + 8
    hex_ = ' '.join(f'{b:02x}' for b in data[s:e])
    asc  = ''.join(chr(b) if 32 <= b < 127 else '.' for b in data[s:e])
    print(f'@0x{j:04x}: {hex_}')
    print(f'         {asc}')
    i = j + 1
