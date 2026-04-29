#!/usr/bin/env python3
"""
gen-iccp-pcap.py — synthesize a realistic-but-fictional ICCP / TASE.2 pcap.

Produces a legacy pcap with structurally realistic ICCP traffic:
  - 5 long-lived bilateral associations between fictional utility codenames
  - Cyclic InformationReports (Block 2 transfer sets) at 1 s / 4 s / 60 s
  - Spontaneous reports interleaved with the cyclic ones
  - Structured datasets carrying floats + TASE.2 quality bytes and status ints
  - A few Write-Request control commands (LFC ΔMW-style)
  - Proper ACSE Initiate / Conclude bookends per association
  - RFC 5737 documentation IPs (192.0.2.0/24, 198.51.100.0/24)

Every peer codename, bilateral domain, dataset name, transfer set name and
point name is drawn from a fictional wordlist embedded in this file. The
output cannot be linked back to any real-world utility traffic.

Note: this is a synthetic capture. We encode just enough of the full
TPKT / COTP / SES / PRES / MMS layer chain that Wireshark's stock MMS
dissector (and our iccp post-dissector) can parse it — we do not
implement the full ISO 8327 / 8823 state machine. PDUs are sent without
session connect/disconnect SPDUs, with a minimal Presentation context
list, and the MMS PDUs are encoded directly.

SPDX-License-Identifier: GPL-2.0-or-later
"""

import argparse
import random
import struct
from pathlib import Path


# -----------------------------------------------------------------------------
# BER helpers
# -----------------------------------------------------------------------------

def _ber_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    if n < 0x100:
        return bytes([0x81, n])
    if n < 0x10000:
        return b'\x82' + struct.pack('>H', n)
    return b'\x83' + struct.pack('>I', n)[1:]


def ber(tag, content: bytes) -> bytes:
    if isinstance(tag, int):
        tag = bytes([tag])
    return tag + _ber_len(len(content)) + content


def ber_int(tag: int, n: int) -> bytes:
    if n == 0:
        body = b'\x00'
    else:
        body = n.to_bytes((n.bit_length() + 8) // 8, 'big', signed=False)
        if body[0] & 0x80:
            body = b'\x00' + body
    return ber(tag, body)


def ber_visible_string(tag: int, s: str) -> bytes:
    return ber(tag, s.encode('ascii'))


# -----------------------------------------------------------------------------
# MMS Data primitives (TASE.2 / Block 2 InformationReport payloads)
# -----------------------------------------------------------------------------
# Data choice tags (IMPLICIT context tags) per ISO 9506 MMS:
#   [1] array          A1 (constructed)
#   [2] structure      A2 (constructed)
#   [3] boolean        83 (primitive)
#   [4] bit-string     84 (primitive)
#   [5] integer        85 (primitive)
#   [6] unsigned       86 (primitive)
#   [7] floating-point 87 (primitive, OCTET STRING)
#   [9] octet-string   89 (primitive)
#  [10] visible-string 8a (primitive)
#  [12] binary-time    8c (primitive)


def mms_data_unsigned(n: int) -> bytes:
    return ber_int(0x86, n)


def mms_data_integer(n: int) -> bytes:
    body = n.to_bytes((n.bit_length() + 8) // 8 or 1, 'big', signed=True)
    return ber(0x85, body)


def mms_data_visible_string(s: str) -> bytes:
    return ber_visible_string(0x8a, s)


def mms_data_floating_point(value: float) -> bytes:
    # TASE.2 floating-point: 1-byte exponent (8 for IEEE754 single) + 4 bytes BE.
    payload = b'\x08' + struct.pack('>f', value)
    return ber(0x87, payload)


def mms_data_bit_string(byte_value: int) -> bytes:
    # Quality byte as 8-bit string: 1 byte unused-bits + 1 data byte.
    return ber(0x84, b'\x00' + bytes([byte_value & 0xff]))


def mms_data_structure(items: list[bytes]) -> bytes:
    return ber(0xa2, b''.join(items))


# -----------------------------------------------------------------------------
# MMS ObjectName + AccessResult + InformationReport
# -----------------------------------------------------------------------------

def mms_object_name_domain_specific(domain_id: str, item_id: str) -> bytes:
    # objectName CHOICE { ... domain-specific [1] IMPLICIT SEQUENCE { domainID, itemID } }
    inner = (ber_visible_string(0x1a, domain_id)
             + ber_visible_string(0x1a, item_id))
    return ber(0xa1, inner)


def mms_access_result_success(data_bytes: bytes) -> bytes:
    # AccessResult ::= CHOICE { failure [0] IMPLICIT DataAccessError, success Data }
    # success is untagged — its own Data choice tag identifies the alternative.
    return data_bytes


def mms_information_report(domain_id: str, item_id: str,
                           access_results: list[bytes]) -> bytes:
    # MMSpdu CHOICE: unconfirmed-PDU [3] IMPLICIT Unconfirmed-PDU
    #   Unconfirmed-PDU ::= SEQUENCE { service Unconfirmed-Service }
    #     [3] IMPLICIT strips the SEQUENCE tag → contents directly inside A3.
    #   Unconfirmed-Service CHOICE: informationReport [0] IMPLICIT InformationReport
    #     [0] IMPLICIT strips the SEQUENCE tag → contents directly inside A0.
    #   InformationReport ::= SEQUENCE {
    #     variableAccessSpecificatn      VariableAccessSpecification,
    #     listOfAccessResult        [0] IMPLICIT SEQUENCE OF AccessResult
    #   }
    #   VariableAccessSpecification CHOICE: variableListName [1] ObjectName (EXPLICIT
    #   because no IMPLICIT keyword → wraps the ObjectName in A1).
    #   ObjectName CHOICE: domain-specific [1] IMPLICIT SEQUENCE { domainID, itemID }
    #     [1] IMPLICIT strips the SEQUENCE tag → contents directly inside A1.
    object_name = mms_object_name_domain_specific(domain_id, item_id)   # A1 LEN <ids>
    var_spec    = ber(0xa1, object_name)                                # variableListName [1] EXPLICIT
    list_results = ber(0xa0, b''.join(access_results))                  # [0] IMPLICIT SEQUENCE OF
    info_report = ber(0xa0, var_spec + list_results)                    # informationReport [0] IMPLICIT
    return ber(0xa3, info_report)                                       # unconfirmed-PDU [3] IMPLICIT


def mms_write_request(invoke_id: int, domain_id: str, item_id: str,
                      data_bytes: bytes) -> bytes:
    # MMSpdu CHOICE: confirmed-RequestPDU [0] IMPLICIT Confirmed-RequestPDU
    # Confirmed-RequestPDU ::= SEQUENCE { invokeID INTEGER, confirmedServiceRequest ... }
    # ConfirmedServiceRequest CHOICE: write [5] IMPLICIT Write-Request
    # Write-Request ::= SEQUENCE {
    #     variableAccessSpecification VariableAccessSpecification,
    #     listOfData              [0] IMPLICIT SEQUENCE OF Data
    # }
    object_name = mms_object_name_domain_specific(domain_id, item_id)
    var_spec    = ber(0xa1, object_name)               # variableListName [1] EXPLICIT
    list_data   = ber(0xa0, data_bytes)                # [0] IMPLICIT SEQUENCE OF Data
    write_req   = ber(0xa5, var_spec + list_data)      # write [5] IMPLICIT
    inv         = ber_int(0x02, invoke_id)
    return ber(0xa0, inv + write_req)                  # confirmed-RequestPDU [0] IMPLICIT


def mms_initiate_request() -> bytes:
    # Minimal MMS Initiate-RequestPDU with sensible defaults.
    # Initiate-RequestPDU ::= SEQUENCE {
    #     localDetailCalling          [0] IMPLICIT Integer32 OPTIONAL,
    #     proposedMaxServOutstandingCalling   [1] IMPLICIT Integer16,
    #     proposedMaxServOutstandingCalled    [2] IMPLICIT Integer16,
    #     proposedDataStructureNestingLevel   [3] IMPLICIT Integer8 OPTIONAL,
    #     mmsInitRequestDetail        [4] IMPLICIT InitRequestDetail
    # }
    body = (ber(0x80, b'\x00\x00\xff\xe7')                        # localDetail 65511
            + ber(0x81, b'\x00\x05')                              # maxServ outstanding calling = 5
            + ber(0x82, b'\x00\x05')                              # maxServ outstanding called = 5
            + ber(0x83, b'\x0a')                                  # nesting level = 10
            + ber(0xa4,                                           # InitRequestDetail
                  ber(0x80, b'\x00\x01')                          # proposedVersionNumber = 1
                  + ber(0x81, b'\x05\xf1\x00')                    # proposedParameterCBB (vendor-typical)
                  + ber(0x82, b'\x07\x83\xff\x80\x00')))          # servicesSupportedCalling
    # MMSpdu CHOICE: initiate-RequestPDU [8] IMPLICIT
    return ber(0xa8, body)


def mms_initiate_response() -> bytes:
    body = (ber(0x80, b'\x00\x00\xff\xe7')
            + ber(0x81, b'\x00\x05')
            + ber(0x82, b'\x00\x05')
            + ber(0x83, b'\x0a')
            + ber(0xa4,
                  ber(0x80, b'\x00\x01')
                  + ber(0x81, b'\x05\xf1\x00')
                  + ber(0x82, b'\x07\x83\xff\x80\x00')))
    # MMSpdu CHOICE: initiate-ResponsePDU [9] IMPLICIT
    return ber(0xa9, body)


def mms_conclude_request() -> bytes:
    # MMSpdu CHOICE: conclude-RequestPDU [11] IMPLICIT NULL
    return ber(0x8b, b'')


def mms_conclude_response() -> bytes:
    return ber(0x8c, b'')


# -----------------------------------------------------------------------------
# Pres / Session layers
# -----------------------------------------------------------------------------
# Wireshark's pres dissector dispatches based on presentation-context-identifier:
# context-id 3 has a well-known mapping to MMS. By using context-id 3 in the
# PDV-list, we get MMS dissection without negotiating a CP-type / CPA-PPDU
# context-list. The session layer stays in the steady "Give-Tokens + DT"
# state for every PDU; we skip CN / AC because their CP-type / CPA-PPDU
# Pres bodies are non-trivial to encode and Wireshark dissects fine without
# them when the data SPDU stream uses a known context-id.
#
# This matches the encoding observed in real ICCP captures, where Wireshark
# parses every steady-state PDU as
#     COTP-DT -> SES (GT) -> SES (DT) -> PRES fully-encoded-data
#         -> single-ASN1-type @ context-id 3 -> MMS

PRES_CONTEXT_ID_MMS = 3


def pres_user_data_mms(mms_pdu: bytes) -> bytes:
    # Fully-encoded-data ::= [APPLICATION 1] IMPLICIT SEQUENCE OF PDV-list
    # PDV-list ::= SEQUENCE {
    #     transfer-syntax-name              [OPTIONAL],
    #     presentation-context-identifier    INTEGER,
    #     presentation-data-values           CHOICE {
    #         single-ASN1-type   [0] ANY,
    #         octet-aligned      [1] IMPLICIT OCTET STRING,
    #         arbitrary          [2] IMPLICIT BIT STRING
    #     }
    # }
    return ber(0x61,
               ber(0x30,
                   ber(0x02, bytes([PRES_CONTEXT_ID_MMS]))
                   + ber(0xa0, mms_pdu)))


def session_data_pdu(pres_pdu: bytes) -> bytes:
    # ISO 8327 steady state: Give-Tokens SPDU (1) length 0, then
    # DATA TRANSFER SPDU (1) length 0, immediately followed by the
    # Pres user-data.
    return b'\x01\x00\x01\x00' + pres_pdu


def cotp_dt(payload: bytes) -> bytes:
    # ISO 8073 COTP DT (Data) PDU: length=2, code=0xf0 (DT), TPDU-NR=0x80 (EOT)
    return b'\x02\xf0\x80' + payload


def tpkt(payload: bytes) -> bytes:
    return b'\x03\x00' + struct.pack('>H', 4 + len(payload)) + payload


# -----------------------------------------------------------------------------
# TCP / IP / Ethernet
# -----------------------------------------------------------------------------

def _csum16(data: bytes) -> int:
    if len(data) & 1:
        data += b'\x00'
    s = 0
    for i in range(0, len(data), 2):
        s += (data[i] << 8) | data[i + 1]
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff


def ip4_packet(src: str, dst: str, ident: int, proto: int, payload: bytes) -> bytes:
    src_b = bytes(int(x) for x in src.split('.'))
    dst_b = bytes(int(x) for x in dst.split('.'))
    total = 20 + len(payload)
    hdr = struct.pack('>BBHHHBBH', 0x45, 0x00, total, ident, 0x4000, 64, proto, 0) + src_b + dst_b
    cs = _csum16(hdr)
    hdr = hdr[:10] + struct.pack('>H', cs) + hdr[12:]
    return hdr + payload


def tcp_segment(src_ip: str, dst_ip: str, sport: int, dport: int,
                seq: int, ack: int, flags: int, payload: bytes) -> bytes:
    src_b = bytes(int(x) for x in src_ip.split('.'))
    dst_b = bytes(int(x) for x in dst_ip.split('.'))
    hdr_len_words = 5
    win = 65535
    tcp_hdr = struct.pack('>HHIIBBHHH',
                          sport, dport, seq & 0xffffffff, ack & 0xffffffff,
                          (hdr_len_words << 4),
                          flags, win, 0, 0)
    pseudo = src_b + dst_b + bytes([0, 6]) + struct.pack('>H', len(tcp_hdr) + len(payload))
    cs = _csum16(pseudo + tcp_hdr + payload)
    tcp_hdr = tcp_hdr[:16] + struct.pack('>H', cs) + tcp_hdr[18:]
    return tcp_hdr + payload


def ethernet_frame(src_mac: bytes, dst_mac: bytes, ip_packet: bytes) -> bytes:
    return dst_mac + src_mac + b'\x08\x00' + ip_packet


# -----------------------------------------------------------------------------
# Pcap writer
# -----------------------------------------------------------------------------

class PcapWriter:
    def __init__(self, path: str):
        self.f = open(path, 'wb')
        # Legacy pcap header: magic, vmajor, vminor, thiszone, sigfigs, snaplen, network=Ethernet(1)
        self.f.write(struct.pack('<IHHiIII',
                                 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))

    def write(self, ts: float, frame: bytes) -> None:
        sec = int(ts)
        usec = int((ts - sec) * 1_000_000)
        self.f.write(struct.pack('<IIII', sec, usec, len(frame), len(frame)))
        self.f.write(frame)

    def close(self):
        self.f.close()


# -----------------------------------------------------------------------------
# Fictional name pool
# -----------------------------------------------------------------------------
# All names below are entirely made-up: not chosen to resemble any real
# utility, TSO, DSO, region, hydro plant or vendor product. They follow
# IEC 60870-6-503 naming conventions structurally (capitals, underscores)
# without naming any real-world entity.

PEER_CODENAMES = [
    'AURORA',     # fictional TSO
    'BLAZE',      # fictional GenCo
    'CINDER',     # fictional DSO
    'DRIFT',      # fictional DSO
    'EMBER',      # fictional GenCo
    'FROST',      # fictional ISO
]

REGION_TOKENS = ['NORD', 'SUD', 'EST', 'OST', 'CTR', 'NRT', 'SRT']
PLANT_TOKENS  = ['UNIT', 'BUS', 'LINE', 'XFMR', 'BKR', 'BAY']
NUMBERS       = ['01', '02', '03', '04', '05', '11', '12', '21', '22']


def fictional_dataset(rng: random.Random, kind: str) -> str:
    # kind in {'ANA','STAT','MIX'} matches DS_ANA_* / DS_STAT_* / DS_MIX_* style.
    suffix = rng.choice(['A_B', 'A_L', 'M_Z', 'S_Z', 'C_R', 'B_R'])
    region = rng.choice(REGION_TOKENS)
    return f'DS_{kind}_{suffix}_{region}'


def fictional_transfer_set(rng: random.Random, peer: str, mode: str) -> str:
    # mode in {'CYCLIC', 'SPONTAN'}. Format: <PEER>_<KIND>_<MODE>.
    # Using fictional codenames only.
    kind = rng.choice(['L', 'N', 'S', 'M'])
    return f'{peer}_{kind}_{mode}'


def fictional_point(rng: random.Random) -> str:
    return f'{rng.choice(REGION_TOKENS)}_{rng.choice(PLANT_TOKENS)}_{rng.choice(NUMBERS)}'


def bilateral_domain(party_a: str, party_b: str) -> str:
    return f'{party_a}_{party_b}'


# -----------------------------------------------------------------------------
# Simulator
# -----------------------------------------------------------------------------

class Peer:
    def __init__(self, name: str, ip: str, mac: bytes):
        self.name = name
        self.ip = ip
        self.mac = mac


class Association:
    """One bilateral ICCP association = one TCP connection from client to hub."""

    def __init__(self, client: Peer, hub: Peer, sport: int, ip_ident_seed: int, rng: random.Random):
        self.client = client
        self.hub = hub
        self.sport = sport
        self.dport = 102
        self.seq_c = 1            # client → hub seq (relative)
        self.seq_h = 1            # hub → client seq
        self.ip_ident = ip_ident_seed
        self.rng = rng

        # Bilateral domain naming: consistent for this peer pair, both directions.
        # Sort alphabetically so AURORA_BLAZE not BLAZE_AURORA.
        a, b = sorted([client.name, hub.name])
        self.domain_ab = f'{a}_{b}'
        self.domain_ba = f'{b}_{a}'

        # Each direction has its own dataset + transfer-set namespace.
        self.client_to_hub_sets = [
            (fictional_transfer_set(rng, client.name, mode), fictional_dataset(rng, kind), period_s)
            for (mode, kind, period_s) in [
                ('CYCLIC',  'ANA',  4.0),
                ('CYCLIC',  'STAT', 4.0),
                ('SPONTAN', 'ANA',  None),
            ]
        ]
        self.hub_to_client_sets = [
            (fictional_transfer_set(rng, hub.name, mode), fictional_dataset(rng, kind), period_s)
            for (mode, kind, period_s) in [
                ('CYCLIC',  'ANA',  1.0),
                ('CYCLIC',  'STAT', 60.0),
                ('SPONTAN', 'STAT', None),
            ]
        ]

    def _next_ident(self) -> int:
        v = self.ip_ident
        self.ip_ident = (self.ip_ident + 1) & 0xffff
        return v

    def _emit(self, src: Peer, dst: Peer, sport: int, dport: int,
              flags: int, payload: bytes, c_to_h: bool) -> bytes:
        if c_to_h:
            seq, ack = self.seq_c, self.seq_h
            self.seq_c += len(payload)
        else:
            seq, ack = self.seq_h, self.seq_c
            self.seq_h += len(payload)
        tcp = tcp_segment(src.ip, dst.ip, sport, dport, seq, ack, flags, payload)
        ip = ip4_packet(src.ip, dst.ip, self._next_ident(), 6, tcp)
        return ethernet_frame(src.mac, dst.mac, ip)

    def syn_handshake(self, t0: float, pcap: PcapWriter):
        # SYN
        f = self._emit(self.client, self.hub, self.sport, self.dport, 0x02, b'', True)
        pcap.write(t0, f)
        self.seq_c = 1            # SYN consumes 1, drop back to 1 for first data
        # SYN-ACK
        f = self._emit(self.hub, self.client, self.dport, self.sport, 0x12, b'', False)
        pcap.write(t0 + 0.0005, f)
        self.seq_h = 1
        # ACK
        f = self._emit(self.client, self.hub, self.sport, self.dport, 0x10, b'', True)
        pcap.write(t0 + 0.001, f)

    def initiate(self, t: float, pcap: PcapWriter) -> float:
        # MMS Initiate-Request, Initiate-Response carried inside the same
        # steady-state Pres+SES wrapper as every other PDU. Wireshark picks
        # them up via context-id 3 → MMS dispatch.
        for direction_pair in [(True, mms_initiate_request),
                               (False, mms_initiate_response)]:
            c_to_h, mms_factory = direction_pair
            mms = mms_factory()
            tp = tpkt(cotp_dt(session_data_pdu(pres_user_data_mms(mms))))
            if c_to_h:
                f = self._emit(self.client, self.hub, self.sport, self.dport, 0x18, tp, True)
            else:
                f = self._emit(self.hub, self.client, self.dport, self.sport, 0x18, tp, False)
            pcap.write(t, f)
            t += 0.005
        return t

    def info_report(self, t: float, pcap: PcapWriter, c_to_h: bool,
                    transfer_set: str, dataset: str, kind: str):
        # Match the visible-item shape of real-world ICCP InformationReports.
        # Wireshark's MMS dissector has a known recursion-depth bug
        # (mms.c:2103) that stops parsing after roughly the second Data
        # item in a SEQUENCE OF — so in practice the iccp dissector only
        # sees items 1-2 of any report, regardless of how many points it
        # actually carries. We emit the *first* AccessResult as the
        # informative one (a header string, an analog point, or a status
        # value) and follow it with a small tail so the report has plausible
        # byte size on the wire.
        shape = self.rng.choices(
            ['header_str', 'analog', 'status', 'quality_only', 'empty'],
            weights=[0.45, 0.25, 0.18, 0.10, 0.02],
        )[0]
        if shape == 'header_str':
            first = mms_data_visible_string(transfer_set)
        elif shape == 'analog':
            first = mms_data_structure([
                mms_data_floating_point(round(self.rng.uniform(-200.0, 5000.0), 3)),
                mms_data_bit_string(self.rng.choice([0x80, 0xc0, 0x40, 0x00])),
            ])
        elif shape == 'status':
            first = mms_data_structure([
                mms_data_integer(self.rng.choice([0, 1, 2, 3])),
                mms_data_bit_string(self.rng.choice([0x80, 0xc0, 0x40, 0x00])),
            ])
        elif shape == 'quality_only':
            first = mms_data_bit_string(self.rng.choice([0x80, 0xc0, 0x40, 0x00]))
        else:
            first = mms_data_unsigned(self.rng.randint(1, 65535))
        results = [mms_access_result_success(first)]
        # Tail: 0-3 extra primitive items so reports vary in size on the wire
        # without re-triggering the recursion bug at unhelpful offsets.
        for _ in range(self.rng.randint(0, 3)):
            results.append(mms_access_result_success(mms_data_unsigned(self.rng.randint(0, 255))))
        domain = self.domain_ab if c_to_h else self.domain_ba
        mms = mms_information_report(domain, dataset, results)
        pres = pres_user_data_mms(mms)
        sess = session_data_pdu(pres)
        cotp = cotp_dt(sess)
        tp = tpkt(cotp)
        if c_to_h:
            f = self._emit(self.client, self.hub, self.sport, self.dport, 0x18, tp, True)
        else:
            f = self._emit(self.hub, self.client, self.dport, self.sport, 0x18, tp, False)
        pcap.write(t, f)

    def write_request(self, t: float, pcap: PcapWriter, invoke_id: int,
                      point_name: str, value: float):
        # Client → Hub: Write-Request to a fictional LFC ΔMW point.
        data = mms_data_floating_point(value)
        mms = mms_write_request(invoke_id, self.domain_ab, point_name, data)
        pres = pres_user_data_mms(mms)
        sess = session_data_pdu(pres)
        cotp = cotp_dt(sess)
        tp = tpkt(cotp)
        f = self._emit(self.client, self.hub, self.sport, self.dport, 0x18, tp, True)
        pcap.write(t, f)


# -----------------------------------------------------------------------------
# Top-level simulation
# -----------------------------------------------------------------------------

def simulate(out_path: str, duration_s: float, seed: int):
    rng = random.Random(seed)
    pcap = PcapWriter(out_path)

    # Hub TSO at 192.0.2.10. Five remote peers on 192.0.2.20–24.
    hub = Peer('AURORA', '192.0.2.10', b'\x02\x00\x00\xaa\x00\x10')
    peer_pool = [
        Peer('BLAZE',  '192.0.2.20', b'\x02\x00\x00\xbb\x00\x14'),
        Peer('CINDER', '192.0.2.21', b'\x02\x00\x00\xcc\x00\x15'),
        Peer('DRIFT',  '192.0.2.22', b'\x02\x00\x00\xdd\x00\x16'),
        Peer('EMBER',  '192.0.2.23', b'\x02\x00\x00\xee\x00\x17'),
        Peer('FROST',  '192.0.2.24', b'\x02\x00\x00\xff\x00\x18'),
    ]

    base_ts = 1_777_536_000.0  # 2026-04-29 12:00:00 UTC, fixed for reproducibility
    associations = []
    for i, peer in enumerate(peer_pool):
        sport = 50000 + i
        ip_seed = (i + 1) * 0x1000
        a = Association(peer, hub, sport, ip_seed, rng)
        a.syn_handshake(base_ts + i * 0.05, pcap)
        associations.append(a)

    # Initiate per association.
    for i, a in enumerate(associations):
        a.initiate(base_ts + 0.5 + i * 0.05, pcap)

    # Schedule cyclic + spontaneous reports for `duration_s` seconds of sim time.
    events: list[tuple[float, callable]] = []
    invoke_id = [1]

    def schedule_cyclic(a: Association, c_to_h: bool, ts: tuple):
        name, dataset, period = ts
        if period is None:
            return
        # First fire 1.0 s after Initiate ends; then every period seconds.
        t = base_ts + 2.0 + rng.uniform(0, period)
        kind = 'ANA' if 'ANA' in dataset else 'STAT'
        while t < base_ts + duration_s:
            events.append((t, lambda tt=t, ak=a, ch=c_to_h, n=name, d=dataset, k=kind:
                           ak.info_report(tt, pcap, ch, n, d, k)))
            t += period

    def schedule_spontaneous(a: Association, c_to_h: bool, ts: tuple, rate_per_min: float):
        name, dataset, _ = ts
        kind = 'ANA' if 'ANA' in dataset else 'STAT'
        # Poisson-ish: small probability each second.
        t = base_ts + 5.0
        end = base_ts + duration_s
        while t < end:
            gap = rng.expovariate(rate_per_min / 60.0)
            t += gap
            if t >= end:
                break
            events.append((t, lambda tt=t, ak=a, ch=c_to_h, n=name, d=dataset, k=kind:
                           ak.info_report(tt, pcap, ch, n, d, k)))

    def schedule_writes(a: Association):
        # Client sends a few bilateral set-points across the run.
        t = base_ts + 30.0
        end = base_ts + duration_s
        while t < end:
            t += rng.uniform(45.0, 90.0)
            if t >= end:
                break
            point = f'{a.client.name}_LFC_REG_S_DELTAMW'
            value = round(rng.uniform(-50.0, 50.0), 2)
            iv = invoke_id[0]; invoke_id[0] += 1
            events.append((t, lambda tt=t, ak=a, p=point, v=value, i=iv:
                           ak.write_request(tt, pcap, i, p, v)))

    for a in associations:
        for ts in a.client_to_hub_sets:
            if ts[2] is not None:
                schedule_cyclic(a, c_to_h=True, ts=ts)
            else:
                schedule_spontaneous(a, c_to_h=True, ts=ts, rate_per_min=2.0)
        for ts in a.hub_to_client_sets:
            if ts[2] is not None:
                schedule_cyclic(a, c_to_h=False, ts=ts)
            else:
                schedule_spontaneous(a, c_to_h=False, ts=ts, rate_per_min=1.0)
        schedule_writes(a)

    events.sort(key=lambda e: e[0])
    for _, fn in events:
        fn()

    # Conclude per association at the end.
    for i, a in enumerate(associations):
        t = base_ts + duration_s + 0.5 + i * 0.05
        mms = mms_conclude_request()
        pres = pres_user_data_mms(mms)
        sess = session_data_pdu(pres)
        tp = tpkt(cotp_dt(sess))
        f = a._emit(a.client, a.hub, a.sport, a.dport, 0x18, tp, True)
        pcap.write(t, f)
        mms = mms_conclude_response()
        pres = pres_user_data_mms(mms)
        sess = session_data_pdu(pres)
        tp = tpkt(cotp_dt(sess))
        f = a._emit(a.hub, a.client, a.dport, a.sport, 0x18, tp, False)
        pcap.write(t + 0.005, f)

    pcap.close()
    return len(events)


def main():
    ap = argparse.ArgumentParser(description=__doc__.split('\n\n')[0],
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('-o', '--output', default='pcaps/generated/iccp-fictional.pcap',
                    help='Output pcap path (default: pcaps/generated/iccp-fictional.pcap)')
    ap.add_argument('--duration', type=float, default=300.0,
                    help='Seconds of simulated traffic (default: 300)')
    ap.add_argument('--seed', type=int, default=20260429,
                    help='RNG seed for reproducibility (default: 20260429)')
    args = ap.parse_args()

    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    n = simulate(str(out), args.duration, args.seed)
    print(f'wrote {out}: {n} report/write events over {args.duration}s simulated time '
          f'(seed={args.seed})')


if __name__ == '__main__':
    main()
