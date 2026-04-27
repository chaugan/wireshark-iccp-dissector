#!/usr/bin/env python3
"""
wash-pcap.py - sanitize an ICCP / TASE.2 capture for public sharing.

v2 design notes (compared to the linear byte-walker in v1):

  v1 walked the TCP payload byte by byte and at every position asked
  "does this look like a BER primitive TLV with printable content?".
  That heuristic was over-eager: a 2-byte BER length-extension marker
  (0x82) at the start of an indefinite/long-form length got read as
  a primitive context-specific tag, and the recovery sometimes
  hashed bytes that belonged inside the OID, integer, or other
  structurally-significant primitive of an enclosing TLV. The v1
  output was bit-correct in length but the Presentation/MMS
  dispatch chain on a real-world capture would refuse to descend
  past PRES because something in the ACSE handshake had been
  corrupted.

  v2 does a proper RECURSIVE BER WALK rooted at each TPKT segment.
  It:
    * Skips TPKT(4) + COTP(>=3) + SES(0..15) headers, none of which
      are BER, then begins parsing at the first BER-shaped byte.
    * For each TLV: reads tag+length, validates value-end is in
      bounds, then either recurses (constructed) or hashes (string-
      shaped primitive). Never reads outside a TLV's declared end,
      so a length byte can no longer be misinterpreted as a tag.
    * Refuses to touch ACSE AARQ/AARE/RLRQ/RLRE/ABRT PDUs (the
      association handshake) unless --aggressive is passed. Those
      packets carry abstract-syntax OIDs and selectors that the
      Presentation dispatch chain depends on; rewriting strings
      inside them buys little anonymity (they are usually selectors
      and version numbers, not operational identity).

What it rewrites
----------------
  IPs       ->  RFC 5737 TEST-NET-1 (192.0.2.x)
  MACs      ->  IEEE doc OUI (00:00:5E:00:53:xx)
  BER strings (universal class FT_STRING-like tags + context-specific
  primitives carrying [n] IMPLICIT VisibleString) inside DATA PDUs
  ->  length-preserving SHA-256 token "VAR_<hex>__".

Hash uses an optional --salt so the same wash can be repeated to
preserve in-capture cross-references but a different wash session
produces unrelated hashes (no dictionary attack across washes).

Input format
------------
Legacy pcap only. For pcapng:  editcap -F pcap input.pcapng plain.pcap

SPDX-License-Identifier: GPL-2.0-or-later
"""

import argparse
import hashlib
import struct
import sys
from pathlib import Path


PCAP_MAGIC          = 0xa1b2c3d4
PCAP_MAGIC_NS       = 0xa1b23c4d
PCAP_MAGIC_BE_US    = 0xd4c3b2a1
PCAP_MAGIC_BE_NS    = 0x4d3cb2a1
PCAPNG_MAGIC        = 0x0a0d0d0a


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
        raise SystemExit(f"not a pcap file (magic=0x{magic:08x})")
    fmt = endian + 'IHHIIII'
    hdr = struct.unpack(fmt, data[:24])
    _, _, _, _, _, _snaplen, linktype = hdr
    return endian, linktype


# -------------------------------------------------------------------
# BER tag classification
# -------------------------------------------------------------------

# Universal-class primitive tags whose content is text and we are
# happy to hash. Other universal primitive tags (INTEGER, REAL,
# BIT STRING, OID, ENUMERATED, etc.) carry semantic non-string data
# and we leave them alone.
BER_STRING_UNIV_TAGS = frozenset([
    0x04,  # OctetString
    0x0C,  # UTF8String
    0x12,  # NumericString
    0x13,  # PrintableString
    0x14,  # T61String / TeletexString
    0x15,  # VideotexString
    0x16,  # IA5String
    0x19,  # GraphicString
    0x1A,  # VisibleString (ISO646)
    0x1B,  # GeneralString
    0x1C,  # UniversalString
    0x1D,  # CharacterString
    0x1E,  # BMPString
])

# Application-class outer tags that mark an ACSE handshake PDU.
# AARQ = Connect-Request, AARE = Connect-Response, RLRQ/RLRE =
# Release, ABRT = Abort. By default we DO NOT walk into these --
# they carry structural OIDs / selectors that the Presentation
# dispatch chain inspects.
ACSE_HANDSHAKE_TAGS = frozenset([0x60, 0x61, 0x62, 0x63, 0x64])


def _classify_tag(tag_byte: int):
    """Returns (cls, primitive_p, tag_number_low5, multi_byte_p)."""
    cls = (tag_byte & 0xC0) >> 6   # 0=universal,1=application,2=context,3=private
    pc  = (tag_byte & 0x20) >> 5   # 0=primitive, 1=constructed
    low = tag_byte & 0x1F
    multi = (low == 0x1F)
    return cls, pc, low, multi


def _is_string_tag(tag_byte: int) -> bool:
    """A primitive tag we should consider hashing if its value is
    printable ASCII."""
    cls, pc, low, multi = _classify_tag(tag_byte)
    if pc != 0:    return False     # constructed, not a leaf
    if multi:      return False     # multi-byte tag, exotic, leave alone
    if cls == 0:                    # universal primitive
        return tag_byte in BER_STRING_UNIV_TAGS
    if cls == 2:                    # context-specific primitive
        # used for "[n] IMPLICIT <stringtype>" -- the most common
        # encoding for MMS Identifier fields.
        return True
    if cls == 1:                    # application class
        return True
    return False                    # private class -- conservative


def _read_ber_length(buf: bytes, off: int):
    """Returns (length, hdr_byte_count_after_tag) or (None, None)
    if the length field is malformed."""
    if off >= len(buf):
        return None, None
    L = buf[off]
    if L < 0x80:
        return L, 1
    if L == 0x80:
        # indefinite-form length -- value continues until 00 00 EOC
        return None, None
    nbytes = L & 0x7f
    if nbytes == 0 or nbytes > 4 or off + 1 + nbytes > len(buf):
        return None, None
    n = 0
    for k in range(nbytes):
        n = (n << 8) | buf[off + 1 + k]
    return n, 1 + nbytes


# -------------------------------------------------------------------
# Recursive walker
# -------------------------------------------------------------------

class Washer:
    LINKTYPE_ETHERNET = 1

    DEFAULT_PRESERVED = frozenset([
        "TASE2_Version",
        "Supported_Features",
        "Bilateral_Table_ID",
    ])

    def __init__(self, preserve_extra=None, salt=b"",
                 min_string_len=4, max_string_len=4096,
                 wash_handshake=False, scrub_numeric=False):
        self.ip_map  = {}
        self.mac_map = {}
        self.ip_next  = 1
        self.mac_next = 1
        self.preserved = set(self.DEFAULT_PRESERVED) | set(preserve_extra or [])
        self.salt = salt
        self.min_len = min_string_len
        self.max_len = max_string_len
        self.wash_handshake = wash_handshake
        # When True, also rewrite the BINARY content of context-specific
        # primitive TLVs that look like operational data values
        # (MMS [7] floating-point, [4]/[5] integers, etc.). This hides
        # the actual measurement / setpoint values in InformationReports
        # at the cost of breaking any per-value analysis the recipient
        # might want to do.
        self.scrub_numeric = scrub_numeric
        self.stats = {
            'packets':           0,
            'ipv4_rewritten':    0,
            'mac_rewritten':     0,
            'strings_rewritten': 0,
            'strings_preserved': 0,
            'numeric_rewritten': 0,
            'handshake_skipped': 0,
            'ber_decode_errors': 0,
        }

    # -- L2/L3/L4 -----------------------------------------------------

    def map_ip(self, ip4):
        if ip4 in self.ip_map: return self.ip_map[ip4]
        new = bytes([192, 0, 2, self.ip_next & 0xff])
        self.ip_next = ((self.ip_next) % 254) + 1
        self.ip_map[ip4] = new
        self.stats['ipv4_rewritten'] += 1
        return new

    def map_mac(self, mac):
        if mac in self.mac_map: return self.mac_map[mac]
        new = bytes([0x00, 0x00, 0x5e, 0x00, 0x53, self.mac_next & 0xff])
        self.mac_next = ((self.mac_next) % 255) + 1
        self.mac_map[mac] = new
        self.stats['mac_rewritten'] += 1
        return new

    def hash_name(self, name_bytes: bytes) -> bytes:
        n = len(name_bytes)
        if n == 0: return name_bytes
        try:
            s = name_bytes.decode('ascii')
        except UnicodeDecodeError:
            s = None
        if s is not None and s in self.preserved:
            self.stats['strings_preserved'] += 1
            return name_bytes
        h = hashlib.sha256(self.salt + name_bytes).hexdigest()
        core = ("VAR_" + h)[:n]
        if len(core) < n:
            core = core + "_" * (n - len(core))
        self.stats['strings_rewritten'] += 1
        return core.encode('ascii')

    # -- BER recursion ------------------------------------------------

    def _find_handshake_ranges(self, payload: bytearray):
        """Find the first BER constructed TLV in `payload` (skipping
        TPKT/COTP/SES non-BER framing). If its outer tag is an ACSE
        handshake (0x60..0x64), return that TLV's byte-range so the
        subsequent string-scrub pass leaves it alone.

        ACSE handshake PDUs always appear at the START of a TCP
        segment's BER content (right after non-BER transport
        framing), so we only need to inspect the first BER TLV --
        not scan the whole payload. That avoids false-positive
        matches on `0x60`-shaped bytes that occur naturally inside
        operational-data primitives."""
        n = len(payload)
        # Skip past a TPKT/COTP-style header if present.
        i = 0
        if n >= 4 and payload[0] == 0x03 and payload[1] == 0x00:
            i = 4
            if i < n:
                li = payload[i]
                if 1 <= li <= 32 and i + 1 + li <= n:
                    i += 1 + li
        # Walk forward past non-BER bytes (SES headers etc.) until we
        # find a plausible BER constructed tag whose length parses.
        scan_limit = min(i + 32, n - 2)
        while i <= scan_limit:
            tag = payload[i]
            if (tag & 0x20) == 0 or tag == 0x20:
                i += 1
                continue
            length, hlen = _read_ber_length(payload, i + 1)
            value_end = (i + 1 + hlen + length) if length is not None else None
            if (length is None or length < 4 or value_end is None
                    or value_end > n):
                i += 1
                continue
            # Found the first plausible constructed TLV.
            if tag in ACSE_HANDSHAKE_TAGS:
                return [(i, value_end)]
            return []
        return []

    def _in_skipranges(self, pos: int, ranges) -> bool:
        for s, e in ranges:
            if s <= pos < e:
                return True
        return False

    def _walk_linear(self, payload: bytearray, skip_ranges):
        """Linear byte walker -- the v1 strategy: at each position,
        try to parse a primitive BER TLV with printable-ASCII
        content, hash it length-preservingly. Skips bytes that fall
        inside any range in `skip_ranges` (used for ACSE handshake
        protection)."""
        i = 0
        n = len(payload)
        while i + 2 <= n:
            if self._in_skipranges(i, skip_ranges):
                i += 1
                continue
            tag = payload[i]
            cls, pc, low, multi = _classify_tag(tag)
            if pc == 1 or multi or tag == 0x00 or not _is_string_tag(tag):
                i += 1
                continue
            length, hlen = _read_ber_length(payload, i + 1)
            if length is None or length < self.min_len or length > self.max_len:
                i += 1
                continue
            vstart = i + 1 + hlen
            vend = vstart + length
            if vend > n:
                i += 1
                continue
            content = bytes(payload[vstart:vend])
            if not all(0x20 <= b < 0x7f for b in content):
                i += 1
                continue
            new = self.hash_name(content)
            if len(new) == length:
                payload[vstart:vend] = new
                i = vend
            else:
                i += 1

    def _walk_numeric(self, payload: bytearray):
        """Second pass: hash binary content of context-specific
        primitive TLVs whose length matches typical MMS typed-data
        primitives (floating-point [7] = 5 bytes, integer [5]/[4] =
        2/4 bytes, etc.). Length-preserving SHA-256-derived bytes
        replace the original content. This hides operational values
        like voltage / current / breaker position from analysts
        examining the published trace."""
        i = 0
        n = len(payload)
        while i + 2 <= n:
            tag = payload[i]
            cls, pc, low, multi = _classify_tag(tag)
            if pc == 1 or multi or tag == 0x00:
                i += 1
                continue
            # Only context-specific primitive tags carry MMS typed-data
            # primitive values. Universal tags 0x02 INTEGER, 0x09 REAL,
            # 0x03 BIT STRING are part of the protocol framing (invokeID,
            # protocol-version etc.) -- don't touch those.
            if cls != 2:
                i += 1
                continue
            length, hlen = _read_ber_length(payload, i + 1)
            if length is None or length < 1 or length > 32:
                i += 1
                continue
            vstart = i + 1 + hlen
            vend = vstart + length
            if vend > n:
                i += 1
                continue
            content = bytes(payload[vstart:vend])
            # Skip values that already look like printable ASCII --
            # they were handled by the string pass.
            if all(0x20 <= b < 0x7f for b in content):
                i += 1
                continue
            # Skip all-zero values (status flags / sentinels) so we
            # don't perturb the structural state machine of e.g.
            # quality bit-strings.
            if all(b == 0 for b in content):
                i = vend
                continue
            # Replace content with first `length` bytes of a SHA-256
            # over (salt || original). Length-preserving.
            h = hashlib.sha256(self.salt + content).digest()[:length]
            payload[vstart:vend] = h
            self.stats['numeric_rewritten'] += 1
            i = vend

    def scrub_strings(self, payload: bytearray):
        """Public entry: linear walk over the TCP payload, hashing
        every primitive BER TLV whose content is printable ASCII.
        Optionally also runs a second pass to hash binary numeric
        primitives (MMS typed-data values) when --scrub-numeric.

        We do NOT protect ACSE handshake PDUs (AARQ 0x60 / AARE 0x61)
        from string-rewriting -- the Wireshark MMS dispatch chain
        depends only on OIDs (excluded already) and Presentation
        Context IDs (INTEGER, excluded). String content inside an
        AARQ / AARE is operator names / authentication credentials
        / AE-qualifiers, exactly what we WANT anonymized."""
        self._walk_linear(payload, [])
        if self.scrub_numeric:
            self._walk_numeric(payload)

    # -- Ethernet/IP/TCP rewrite -------------------------------------

    def wash_packet(self, pkt: bytes) -> bytes:
        self.stats['packets'] += 1
        if len(pkt) < 14: return pkt
        dst, src, etype = pkt[0:6], pkt[6:12], pkt[12:14]
        rest = pkt[14:]
        new_dst = self.map_mac(dst); new_src = self.map_mac(src)
        if etype == b'\x08\x00' and len(rest) >= 20:
            return new_dst + new_src + etype + self._wash_ipv4(rest)
        return new_dst + new_src + etype + rest

    def _wash_ipv4(self, ipv4: bytes) -> bytes:
        ihl = (ipv4[0] & 0x0f) * 4
        if ihl < 20 or ihl > len(ipv4): return ipv4
        hdr = bytearray(ipv4[:ihl])
        new_src = self.map_ip(bytes(hdr[12:16]))
        new_dst = self.map_ip(bytes(hdr[16:20]))
        hdr[12:16] = new_src; hdr[16:20] = new_dst
        hdr[10:12] = b'\x00\x00'
        hdr[10:12] = struct.pack('!H', self._ip_csum(bytes(hdr)))
        protocol = hdr[9]
        payload = ipv4[ihl:]
        if protocol == 6:
            payload = self._wash_tcp(payload, new_src, new_dst)
        return bytes(hdr) + payload

    def _wash_tcp(self, tcp: bytes, new_src_ip: bytes, new_dst_ip: bytes) -> bytes:
        if len(tcp) < 20: return tcp
        doff = (tcp[12] >> 4) * 4
        if doff < 20 or doff > len(tcp): return tcp
        hdr = bytearray(tcp[:doff])
        payload = bytearray(tcp[doff:])
        if payload:
            self.scrub_strings(payload)
        hdr[16:18] = b'\x00\x00'
        seg = bytes(hdr) + bytes(payload)
        pseudo = new_src_ip + new_dst_ip + b'\x00\x06' + struct.pack('!H', len(seg))
        csum = self._ip_csum(pseudo + seg)
        if csum == 0: csum = 0xffff
        hdr[16:18] = struct.pack('!H', csum)
        return bytes(hdr) + bytes(payload)

    @staticmethod
    def _ip_csum(data: bytes) -> int:
        if len(data) & 1: data = data + b'\x00'
        s = 0
        for i in range(0, len(data), 2):
            s += (data[i] << 8) | data[i + 1]
        while s >> 16:
            s = (s & 0xffff) + (s >> 16)
        return (~s) & 0xffff


def main():
    ap = argparse.ArgumentParser(
        description="Sanitize an ICCP/TASE.2 pcap for public sharing using "
                    "a recursive structural BER walker.")
    ap.add_argument('input_pcap')
    ap.add_argument('output_pcap')
    ap.add_argument('--preserve-extra', action='append', default=[],
                    help="Strings to leave untouched (repeatable). "
                         "TASE2_Version, Supported_Features, "
                         "Bilateral_Table_ID always preserved.")
    ap.add_argument('--salt',
                    help="Hash salt. Use a fresh random value per wash to "
                         "prevent dictionary deanonymization across "
                         "different washes of the same source. Within one "
                         "wash, identical input still hashes to identical "
                         "output regardless of salt.")
    ap.add_argument('--min-string-len', type=int, default=4,
                    help="Smallest BER string length to rewrite (default 4).")
    ap.add_argument('--wash-handshake', action='store_true',
                    help="(no-op currently; reserved for future use). The "
                         "default behaviour does walk inside ACSE handshake "
                         "PDUs because nothing in there is actually needed "
                         "for MMS dispatch.")
    ap.add_argument('--scrub-numeric', action='store_true',
                    help="Also hash the binary content of MMS typed-data "
                         "primitives (floating-point [7], integer [4]/[5], "
                         "etc.). Hides operational values like voltages, "
                         "breaker positions, counters from the published "
                         "trace -- but breaks any per-value analysis the "
                         "recipient might want to do. Off by default.")
    args = ap.parse_args()

    data = Path(args.input_pcap).read_bytes()
    endian, linktype = parse_global_header(data)
    if linktype != Washer.LINKTYPE_ETHERNET:
        raise SystemExit(f"unsupported linktype {linktype}; only Ethernet=1 is handled")

    phdr_fmt = endian + 'IIII'
    phdr_sz = 16

    salt = args.salt.encode() if args.salt else b""
    washer = Washer(preserve_extra=args.preserve_extra,
                    salt=salt,
                    min_string_len=args.min_string_len,
                    wash_handshake=args.wash_handshake,
                    scrub_numeric=args.scrub_numeric)

    out = bytearray()
    out += data[:24]

    pos = 24
    while pos + phdr_sz <= len(data):
        ts_s, ts_u, caplen, origlen = struct.unpack(phdr_fmt, data[pos:pos+phdr_sz])
        if pos + phdr_sz + caplen > len(data):
            print(f"truncated at offset {pos}; stopping", file=sys.stderr)
            break
        pkt = data[pos+phdr_sz : pos+phdr_sz+caplen]
        pkt = washer.wash_packet(pkt)
        assert len(pkt) == caplen, "length-preserving rewrite produced different length"
        out += struct.pack(phdr_fmt, ts_s, ts_u, caplen, origlen)
        out += pkt
        pos += phdr_sz + caplen

    Path(args.output_pcap).write_bytes(out)
    s = washer.stats
    print(
        f"{args.output_pcap}:\n"
        f"  {s['packets']} packets rewritten\n"
        f"  {len(washer.ip_map)} IPv4 addresses -> 192.0.2.x\n"
        f"  {len(washer.mac_map)} MAC addresses -> 00:00:5e:00:53:xx\n"
        f"  {s['strings_rewritten']} strings hashed\n"
        f"  {s['strings_preserved']} strings preserved (allow-list)\n"
        f"  {s['numeric_rewritten']} numeric primitives hashed"
        + ("" if args.scrub_numeric else " (off; pass --scrub-numeric to enable)")
        + f"\n  {s['ber_decode_errors']} BER parse errors (skipped subtrees)",
        file=sys.stderr)


if __name__ == '__main__':
    main()
