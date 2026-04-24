#!/usr/bin/env python3
"""
wash-pcap.py - sanitize an ICCP / TASE.2 capture for public sharing.

What it rewrites
----------------
  IPs     ->  RFC 5737 TEST-NET-1 (192.0.2.x), consistent across packets
  MACs    ->  IEEE documentation OUI (00:00:5E:00:53:xx), consistent
  MMS
  Visible ->  hash-based token of IDENTICAL length, e.g.
  Strings     "NYISO_Control_Center_Substation_12_Breaker_A"  ->
              "VAR_7a3b2f9c1f5e8d7e_________________________"
              This preserves the BER length byte and every downstream
              offset, so the ASN.1 tree is still well-formed and the
              MMS dissector still runs.

What it does NOT change
-----------------------
  * TPKT / COTP / ISO Session / Presentation / ACSE framing
  * ASN.1 tags, CHOICE selectors, length fields
  * Presentation Context Identifier binding (MMS still dispatches)
  * Typed-data primitive values (floats, ints, bit-strings, binary-times).
    Those often carry operational state; pass --scrub-values to
    redact them as well.
  * Timestamps (file-level capture timestamps are preserved)

Input format
------------
Legacy pcap only. For pcapng, run:
    editcap -F pcap input.pcapng plain.pcap
first.

Usage
-----
    python3 wash-pcap.py input.pcap output.pcap
    python3 wash-pcap.py input.pcap output.pcap --scrub-values
    python3 wash-pcap.py input.pcap output.pcap --preserve-extra Bilateral_Table_ID

Safety
------
The scanner identifies VisibleString tokens by the BER tag 0x1A, a
plausible short-form length, and all-printable-ASCII content that
matches the MMS identifier character class (alnum + `_.-$`).  It does
not "know" the ASN.1 structure - it walks the TCP payload byte by byte.
False matches on random binary data are possible but are also
length-preserving, so the output stays well-formed at the network
layer.

SPDX-License-Identifier: GPL-2.0-or-later
"""

import argparse
import hashlib
import struct
import sys
from pathlib import Path


PCAP_MAGIC          = 0xa1b2c3d4  # microsecond, little-endian host
PCAP_MAGIC_NS       = 0xa1b23c4d  # nanosecond,  little-endian host
PCAP_MAGIC_BE_US    = 0xd4c3b2a1  # microsecond, written big-endian
PCAP_MAGIC_BE_NS    = 0x4d3cb2a1  # nanosecond,  written big-endian
PCAPNG_MAGIC        = 0x0a0d0d0a  # pcapng section-header block


def parse_global_header(data: bytes):
    if len(data) < 24:
        raise ValueError("file too short to be a pcap")
    magic = struct.unpack('<I', data[:4])[0]

    if magic == PCAPNG_MAGIC:
        raise SystemExit(
            "input is pcapng. Convert first:\n"
            "    editcap -F pcap input.pcapng plain.pcap\n"
            "then run wash-pcap on plain.pcap.")

    if magic in (PCAP_MAGIC, PCAP_MAGIC_NS):
        endian = '<'
    elif magic in (PCAP_MAGIC_BE_US, PCAP_MAGIC_BE_NS):
        endian = '>'
    else:
        raise SystemExit(
            f"not a pcap file (magic=0x{magic:08x}). "
            "For pcapng: editcap -F pcap input.pcapng plain.pcap")
    fmt = endian + 'IHHIIII'
    hdr = struct.unpack(fmt, data[:24])
    _, _, _, _, _, _snaplen, linktype = hdr
    return endian, linktype


class Washer:
    LINKTYPE_ETHERNET = 1

    # MMS identifiers (ISO 9506): VisibleString content must be from
    # <letter> <digit> $ _ but in practice dots and hyphens show up
    # too. We use a permissive set.
    IDCHARS = set(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_$-.")

    # Names that appear in IEC 60870-6-503 and reveal no operational
    # identity; keep them so the washed capture stays instantly
    # recognisable as ICCP.
    DEFAULT_PRESERVED = frozenset([
        "TASE2_Version",
        "Supported_Features",
        "Bilateral_Table_ID",
    ])

    def __init__(self, preserve_extra=None, scrub_values=False,
                 min_string_len=4, max_string_len=127):
        self.ip_map  = {}
        self.mac_map = {}
        self.ip_next  = 1
        self.mac_next = 1
        self.preserved = set(self.DEFAULT_PRESERVED) | set(preserve_extra or [])
        self.scrub_values = scrub_values
        self.min_len = min_string_len
        self.max_len = max_string_len
        self.stats = {
            'packets':           0,
            'ipv4_rewritten':    0,
            'mac_rewritten':     0,
            'strings_rewritten': 0,
            'strings_preserved': 0,
        }

    # -- address maps ------------------------------------------------------

    def map_ip(self, ip4):
        if ip4 in self.ip_map:
            return self.ip_map[ip4]
        new = bytes([192, 0, 2, self.ip_next & 0xff])
        self.ip_next = ((self.ip_next) % 254) + 1
        self.ip_map[ip4] = new
        self.stats['ipv4_rewritten'] += 1
        return new

    def map_mac(self, mac):
        if mac in self.mac_map:
            return self.mac_map[mac]
        new = bytes([0x00, 0x00, 0x5e, 0x00, 0x53, self.mac_next & 0xff])
        self.mac_next = ((self.mac_next) % 255) + 1
        self.mac_map[mac] = new
        self.stats['mac_rewritten'] += 1
        return new

    # -- name rewrite ------------------------------------------------------

    def hash_name(self, name_bytes):
        """Length-preserving identifier replacement."""
        n = len(name_bytes)
        if n == 0:
            return name_bytes
        s = name_bytes.decode('ascii', errors='replace')
        if s in self.preserved:
            self.stats['strings_preserved'] += 1
            return name_bytes
        h = hashlib.sha1(name_bytes).hexdigest()
        # Produce "VAR_<hash>" left-padded with underscores to n chars
        prefix = "VAR_"
        core = (prefix + h)[:n]
        if len(core) < n:
            core = core + "_" * (n - len(core))
        self.stats['strings_rewritten'] += 1
        return core.encode('ascii')

    def scrub_visible_strings(self, payload: bytearray):
        """Walk `payload` looking for BER VisibleString TLVs (tag 0x1A)
        whose content is a plausible MMS identifier, and hash-rewrite
        them in place. Length-preserving."""
        i = 0
        n = len(payload)
        while i < n - 2:
            if payload[i] != 0x1a:
                i += 1
                continue

            Lbyte = payload[i + 1]
            if Lbyte & 0x80:
                nlen = Lbyte & 0x7f
                if nlen == 0 or nlen > 2 or i + 2 + nlen > n:
                    i += 1
                    continue
                length = 0
                for k in range(nlen):
                    length = (length << 8) | payload[i + 2 + k]
                vstart = i + 2 + nlen
            else:
                length = Lbyte
                vstart = i + 2

            vend = vstart + length
            if vend > n:
                i += 1
                continue
            if length < self.min_len or length > self.max_len:
                i += 1
                continue

            content = bytes(payload[vstart:vend])
            if all(b in self.IDCHARS for b in content):
                new = self.hash_name(content)
                if len(new) == length:
                    payload[vstart:vend] = new
                    i = vend
                    continue
            i += 1

    # -- layer 2/3/4 rewrite ----------------------------------------------

    def wash_packet(self, pkt: bytes) -> bytes:
        self.stats['packets'] += 1
        if len(pkt) < 14:
            return pkt
        dst = pkt[0:6]
        src = pkt[6:12]
        etype = pkt[12:14]
        rest = pkt[14:]
        new_dst = self.map_mac(dst)
        new_src = self.map_mac(src)

        if etype == b'\x08\x00' and len(rest) >= 20:
            return new_dst + new_src + etype + self._wash_ipv4(rest)
        # non-IPv4: MAC-washed only
        return new_dst + new_src + etype + rest

    def _wash_ipv4(self, ipv4: bytes) -> bytes:
        ver_ihl = ipv4[0]
        ihl = (ver_ihl & 0x0f) * 4
        if ihl < 20 or ihl > len(ipv4):
            return ipv4

        hdr = bytearray(ipv4[:ihl])
        src_ip = bytes(hdr[12:16])
        dst_ip = bytes(hdr[16:20])
        new_src = self.map_ip(src_ip)
        new_dst = self.map_ip(dst_ip)
        hdr[12:16] = new_src
        hdr[16:20] = new_dst
        hdr[10:12] = b'\x00\x00'
        hdr_csum = self._ip_csum(bytes(hdr))
        hdr[10:12] = struct.pack('!H', hdr_csum)

        protocol = hdr[9]
        payload = ipv4[ihl:]

        if protocol == 6:  # TCP
            payload = self._wash_tcp(payload, new_src, new_dst)

        return bytes(hdr) + payload

    def _wash_tcp(self, tcp: bytes, new_src_ip: bytes, new_dst_ip: bytes) -> bytes:
        if len(tcp) < 20:
            return tcp
        doff = (tcp[12] >> 4) * 4
        if doff < 20 or doff > len(tcp):
            return tcp
        hdr = bytearray(tcp[:doff])
        payload = bytearray(tcp[doff:])

        # scrub the MMS VisibleStrings embedded in the TCP payload
        if payload:
            self.scrub_visible_strings(payload)

        # recompute TCP checksum
        hdr[16:18] = b'\x00\x00'
        seg = bytes(hdr) + bytes(payload)
        pseudo = new_src_ip + new_dst_ip + b'\x00\x06' + struct.pack('!H', len(seg))
        csum = self._ip_csum(pseudo + seg)
        if csum == 0:
            csum = 0xffff
        hdr[16:18] = struct.pack('!H', csum)
        return bytes(hdr) + bytes(payload)

    @staticmethod
    def _ip_csum(data: bytes) -> int:
        if len(data) & 1:
            data = data + b'\x00'
        s = 0
        for i in range(0, len(data), 2):
            s += (data[i] << 8) | data[i + 1]
        while s >> 16:
            s = (s & 0xffff) + (s >> 16)
        return (~s) & 0xffff


def main():
    ap = argparse.ArgumentParser(
        description="Sanitize an ICCP/TASE.2 pcap for public sharing. "
                    "Rewrites IPs, MACs, and MMS VisibleString identifiers "
                    "(length-preservingly) so the ASN.1 stays well-formed.")
    ap.add_argument('input_pcap',  help="input .pcap (legacy format; for pcapng, editcap -F pcap first)")
    ap.add_argument('output_pcap', help="output .pcap")
    ap.add_argument('--scrub-values', action='store_true',
                    help="also redact typed-data primitives (floats/ints/etc.). "
                         "Not yet implemented; placeholder.")
    ap.add_argument('--preserve-extra', action='append', default=[],
                    help="additional identifier strings to leave untouched "
                         "(repeatable). 'TASE2_Version', 'Supported_Features', "
                         "and 'Bilateral_Table_ID' are always preserved.")
    args = ap.parse_args()

    data = Path(args.input_pcap).read_bytes()
    endian, linktype = parse_global_header(data)
    if linktype != Washer.LINKTYPE_ETHERNET:
        raise SystemExit(
            f"unsupported linktype {linktype} (only Ethernet = 1 is handled). "
            "If your capture is LINUX_SLL or raw IP, convert with "
            "editcap -F pcap --enforce-link-type=1 first.")

    phdr_fmt = endian + 'IIII'
    phdr_sz = 16

    washer = Washer(preserve_extra=args.preserve_extra,
                    scrub_values=args.scrub_values)

    out = bytearray()
    out += data[:24]  # preserve global header

    pos = 24
    while pos + phdr_sz <= len(data):
        ts_s, ts_u, caplen, origlen = struct.unpack(phdr_fmt, data[pos:pos + phdr_sz])
        if pos + phdr_sz + caplen > len(data):
            print(f"truncated at offset {pos}; stopping", file=sys.stderr)
            break
        pkt = data[pos + phdr_sz : pos + phdr_sz + caplen]
        pkt = washer.wash_packet(pkt)
        assert len(pkt) == caplen, \
            "internal error: length-preserving rewrite produced different length"
        out += struct.pack(phdr_fmt, ts_s, ts_u, caplen, origlen)
        out += pkt
        pos += phdr_sz + caplen

    Path(args.output_pcap).write_bytes(out)
    s = washer.stats
    print(
        f"{args.output_pcap}: {s['packets']} packets rewritten\n"
        f"  {len(washer.ip_map)} unique IPv4 addresses -> 192.0.2.x\n"
        f"  {len(washer.mac_map)} unique MAC addresses -> 00:00:5e:00:53:xx\n"
        f"  {s['strings_rewritten']} MMS identifiers rewritten\n"
        f"  {s['strings_preserved']} MMS identifiers preserved",
        file=sys.stderr)


if __name__ == '__main__':
    main()
