#!/usr/bin/env python3
"""
anon-ips.py - rewrite every IPv4 address in a pcap to 192.0.2.x.

Only the IPs change. MAC addresses, TCP/UDP ports, payloads, MMS
identifiers, ASN.1 content -- all left exactly as-is. Use this
when sharing an ICCP / TASE.2 capture with someone who needs to
see the protocol detail (variable names, Transfer Set IDs, point
values) but who shouldn't learn your control-center or substation
IPs.

Each distinct source/destination IPv4 maps to 192.0.2.<n> in
first-seen order, n cycling 1..254. The mapping is stable across
a single run (same source IP always rewrites to the same target),
not deterministic across runs.

Recomputes IP header checksum, TCP checksum, and UDP checksum
because the pseudo-header changes when the IPs change. Skips L4
checksum recomputation on IP fragments (the L4 header is split
across fragments, so a partial recompute would be wrong) -- the
fragment is still emitted with new IPs and a fresh IP checksum.

Length-preserving and format-preserving: legacy pcap in -> legacy
pcap out, same magic, same nanosecond resolution. For pcapng input,
convert first:

    editcap -F pcap input.pcapng plain.pcap

SPDX-License-Identifier: GPL-2.0-or-later
"""

import argparse
import struct
import sys
from pathlib import Path


PCAP_MAGIC       = 0xa1b2c3d4
PCAP_MAGIC_NS    = 0xa1b23c4d
PCAP_MAGIC_BE_US = 0xd4c3b2a1
PCAP_MAGIC_BE_NS = 0x4d3cb2a1
PCAPNG_MAGIC     = 0x0a0d0d0a

LINKTYPE_ETHERNET = 1


def parse_global_header(data: bytes):
    if len(data) < 24:
        raise SystemExit("file too short to be a pcap")
    magic = struct.unpack('<I', data[:4])[0]
    if magic == PCAPNG_MAGIC:
        raise SystemExit(
            "input is pcapng. Convert first:\n"
            "    editcap -F pcap input.pcapng plain.pcap\n"
            "then run anon-ips on plain.pcap.")
    if magic in (PCAP_MAGIC, PCAP_MAGIC_NS):
        endian = '<'
    elif magic in (PCAP_MAGIC_BE_US, PCAP_MAGIC_BE_NS):
        endian = '>'
    else:
        raise SystemExit(f"not a pcap file (magic=0x{magic:08x})")
    fmt = endian + 'IHHIIII'
    hdr = struct.unpack(fmt, data[:24])
    _, _, _, _, _, _snaplen, linktype = hdr
    return endian, linktype


def ones_complement_csum(data: bytes) -> int:
    """RFC 1071 16-bit one's-complement checksum over `data`."""
    if len(data) & 1:
        data = data + b'\x00'
    s = 0
    for i in range(0, len(data), 2):
        s += (data[i] << 8) | data[i + 1]
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff


class IPMap:
    """First-seen-order map IPv4 -> 192.0.2.<n>, consistent within a run."""
    def __init__(self):
        self._m = {}
        self._next_n = 1

    def map(self, ip4: bytes) -> bytes:
        if ip4 in self._m:
            return self._m[ip4]
        new = bytes([192, 0, 2, self._next_n & 0xff])
        self._next_n = (self._next_n % 254) + 1
        self._m[ip4] = new
        return new

    def items(self):
        return self._m.items()


def wash_tcp(tcp: bytes, new_src_ip: bytes, new_dst_ip: bytes) -> bytes:
    if len(tcp) < 20:
        return tcp
    doff = (tcp[12] >> 4) * 4
    if doff < 20 or doff > len(tcp):
        return tcp
    hdr = bytearray(tcp[:doff])
    payload = tcp[doff:]
    hdr[16:18] = b'\x00\x00'
    seg = bytes(hdr) + payload
    pseudo = new_src_ip + new_dst_ip + b'\x00\x06' + struct.pack('!H', len(seg))
    csum = ones_complement_csum(pseudo + seg)
    if csum == 0:
        csum = 0xffff
    hdr[16:18] = struct.pack('!H', csum)
    return bytes(hdr) + payload


def wash_udp(udp: bytes, new_src_ip: bytes, new_dst_ip: bytes) -> bytes:
    if len(udp) < 8:
        return udp
    hdr = bytearray(udp[:8])
    payload = udp[8:]
    hdr[6:8] = b'\x00\x00'
    seg = bytes(hdr) + payload
    pseudo = new_src_ip + new_dst_ip + b'\x00\x11' + struct.pack('!H', len(seg))
    csum = ones_complement_csum(pseudo + seg)
    if csum == 0:
        csum = 0xffff
    hdr[6:8] = struct.pack('!H', csum)
    return bytes(hdr) + payload


def wash_ipv4(ipv4: bytes, ipmap: IPMap) -> bytes:
    if len(ipv4) < 20:
        return ipv4
    ihl = (ipv4[0] & 0x0f) * 4
    if ihl < 20 or ihl > len(ipv4):
        return ipv4
    hdr = bytearray(ipv4[:ihl])
    new_src = ipmap.map(bytes(hdr[12:16]))
    new_dst = ipmap.map(bytes(hdr[16:20]))
    hdr[12:16] = new_src
    hdr[16:20] = new_dst
    # Always recompute the IP header checksum.
    hdr[10:12] = b'\x00\x00'
    hdr[10:12] = struct.pack('!H', ones_complement_csum(bytes(hdr)))

    # Skip L4 recompute on fragments -- the TCP/UDP header is split
    # across fragments and a partial-pseudo recompute would corrupt
    # the wire data.
    frag_field = struct.unpack('!H', bytes(hdr[6:8]))[0]
    is_fragment = (frag_field & 0x3fff) != 0
    proto = hdr[9]
    payload = ipv4[ihl:]
    if not is_fragment:
        if proto == 6:
            payload = wash_tcp(payload, new_src, new_dst)
        elif proto == 17:
            payload = wash_udp(payload, new_src, new_dst)
    return bytes(hdr) + payload


def wash_packet(pkt: bytes, ipmap: IPMap) -> bytes:
    if len(pkt) < 14:
        return pkt
    eth_hdr = pkt[:14]
    etype = pkt[12:14]
    rest = pkt[14:]
    if etype == b'\x08\x00' and len(rest) >= 20:
        return eth_hdr + wash_ipv4(rest, ipmap)
    # IPv6 (0x86dd), ARP (0x0806), VLAN-tagged (0x8100), anything
    # else -- pass through unchanged. We only anonymize IPv4 on
    # plain Ethernet here.
    return pkt


def main():
    ap = argparse.ArgumentParser(
        description="Rewrite IPv4 addresses in a pcap to 192.0.2.x. "
                    "Leaves MACs, ports, payloads, ASN.1, MMS, ICCP "
                    "content all intact -- only the IPv4 source/dest "
                    "fields and the affected checksums are rewritten.")
    ap.add_argument('input_pcap')
    ap.add_argument('output_pcap')
    args = ap.parse_args()

    data = Path(args.input_pcap).read_bytes()
    endian, linktype = parse_global_header(data)
    if linktype != LINKTYPE_ETHERNET:
        raise SystemExit(f"unsupported linktype {linktype}; only Ethernet=1 is handled")

    phdr_fmt = endian + 'IIII'
    phdr_sz = 16
    ipmap = IPMap()
    pkt_count = 0

    out = bytearray()
    out += data[:24]

    pos = 24
    while pos + phdr_sz <= len(data):
        ts_s, ts_u, caplen, origlen = struct.unpack(phdr_fmt, data[pos:pos + phdr_sz])
        if pos + phdr_sz + caplen > len(data):
            print(f"truncated at offset {pos}; stopping", file=sys.stderr)
            break
        pkt = bytes(data[pos + phdr_sz : pos + phdr_sz + caplen])
        pkt = wash_packet(pkt, ipmap)
        assert len(pkt) == caplen, "length-preserving rewrite produced different length"
        out += struct.pack(phdr_fmt, ts_s, ts_u, caplen, origlen)
        out += pkt
        pos += phdr_sz + caplen
        pkt_count += 1

    Path(args.output_pcap).write_bytes(out)
    print(f"{args.output_pcap}:", file=sys.stderr)
    print(f"  {pkt_count} packets", file=sys.stderr)
    print(f"  {sum(1 for _ in ipmap.items())} unique IPv4 addresses rewritten:", file=sys.stderr)
    for orig, new in sorted(ipmap.items(), key=lambda kv: tuple(kv[1])):
        a, b, c, d = orig
        x, y, z, w = new
        print(f"    {a}.{b}.{c}.{d}  ->  {x}.{y}.{z}.{w}", file=sys.stderr)


if __name__ == '__main__':
    main()
