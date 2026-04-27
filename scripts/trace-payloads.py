#!/usr/bin/env python3
"""Print first 48 bytes of the first 5 TCP-payload-bearing frames."""
import struct, sys
data = open(sys.argv[1], 'rb').read()
m = data[:4]
endian = '<' if m in (b'\xd4\xc3\xb2\xa1', b'\x4d\x3c\xb2\xa1') else '>'
phdr_fmt = endian + 'IIII'
pos = 24
n = 0
shown = 0
while pos + 16 <= len(data) and shown < 6:
    ts_s, ts_us, caplen, _ = struct.unpack(phdr_fmt, data[pos:pos+16])
    pkt = data[pos+16 : pos+16+caplen]
    pos += 16 + caplen
    n += 1
    if len(pkt) < 14 + 20 + 20 or pkt[12:14] != b'\x08\x00':
        continue
    ihl = (pkt[14] & 0x0f) * 4
    if pkt[14 + 9] != 6:
        continue
    tcp_off = 14 + ihl
    doff = (pkt[tcp_off + 12] >> 4) * 4
    payload = pkt[tcp_off + doff:]
    if len(payload) < 8:
        continue
    shown += 1
    first = payload[:48]
    hex_s = ' '.join(f'{b:02x}' for b in first)
    asc_s = ''.join(chr(b) if 32 <= b < 127 else '.' for b in first)
    print(f'frame {n:3d} paylen={len(payload):4d}: {hex_s}')
    print(f'                       {asc_s}')
