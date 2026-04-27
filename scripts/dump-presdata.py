#!/usr/bin/env python3
"""
Open a pcap file, find the FIRST PRES user-data payload, and print
its hex + ASCII view so we can manually verify whether the bytes
look like a well-formed BER MMS PDU.

This is a quick-and-dirty BER walker that descends:
    Ethernet -> IPv4 -> TCP -> TPKT (3 0 LL LL) -> COTP (LL ...) ->
    SES SPDU (varies) -> PRES PPDU
and stops at the first inner ASN.1 value that follows the PCI.
"""

import struct
import sys
from pathlib import Path

PCAP = Path(sys.argv[1] if len(sys.argv) > 1
            else r'C:\Users\chris\Downloads\iccp_anon.pcap')

raw = PCAP.read_bytes()
endian = '<' if raw[:4] == b'\xa1\xb2\xc3\xd4' else '>'
pos = 24  # global header

found = 0
while pos + 16 <= len(raw) and found < 3:
    ts_s, ts_us, caplen, _ = struct.unpack(endian + 'IIII', raw[pos:pos+16])
    pkt = raw[pos+16:pos+16+caplen]
    pos += 16 + caplen
    if len(pkt) < 14 + 20 + 20:
        continue
    eth_type = pkt[12:14]
    if eth_type != b'\x08\x00':
        continue
    ihl = (pkt[14] & 0x0f) * 4
    proto = pkt[14 + 9]
    if proto != 6:  # TCP
        continue
    tcp_off = 14 + ihl
    doff = (pkt[tcp_off + 12] >> 4) * 4
    payload = pkt[tcp_off + doff:]
    if len(payload) < 4:
        continue
    if payload[0] != 0x03 or payload[1] != 0x00:
        continue  # not TPKT

    found += 1
    print(f'\n========== frame {found} (offset 0x{pos:x}, paylen {len(payload)}) ==========')
    # show TCP payload hex
    for i in range(0, min(len(payload), 192), 32):
        chunk = payload[i:i+32]
        hex_s = ' '.join(f'{b:02x}' for b in chunk)
        asc_s = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
        print(f'  {i:04x}  {hex_s:<96}  {asc_s}')

    # quick TPKT/COTP skip then look for the PRES "fully-encoded-data" pattern
    # PRES typically starts with 0x61 (CPA) or 0x31 (TYPED-DATA Set) or other.
    # Ask user to show us, just dump.
