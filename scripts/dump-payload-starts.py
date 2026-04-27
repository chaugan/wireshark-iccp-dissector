#!/usr/bin/env python3
"""Show the first 32 bytes of every TCP segment in a pcap that has a
non-zero payload, prefixed by frame index. Used for examining where
BER content starts in TPKT/COTP/SES-framed traffic."""
import struct, sys

p = sys.argv[1]
data = open(p, 'rb').read()
endian = '<' if data[:4] in (b'\xa1\xb2\xc3\xd4', b'\xa1\xb2\x3c\x4d') else '>'

pos = 24
n = 0
while pos + 16 <= len(data):
    ts_s, ts_us, caplen, _ = struct.unpack(endian + 'IIII', data[pos:pos+16])
    pkt = data[pos+16 : pos+16+caplen]
    pos += 16 + caplen
    n += 1
    if len(pkt) < 14 + 20 + 20 or pkt[12:14] != b'\x08\x00':
        continue
    ihl = (pkt[14] & 0x0f) * 4
    if pkt[14+9] != 6:
        continue
    tcp_off = 14 + ihl
    doff = (pkt[tcp_off + 12] >> 4) * 4
    payload = pkt[tcp_off + doff:]
    if not payload:
        continue
    first = payload[:32]
    hex_s = ' '.join(f'{b:02x}' for b in first)
    asc_s = ''.join(chr(b) if 32 <= b < 127 else '.' for b in first)
    print(f'F{n:3d} ({len(payload):4d}b)  {hex_s}  |  {asc_s}')
    if n > 30:  # first 30 frames is enough to spot the pattern
        break
