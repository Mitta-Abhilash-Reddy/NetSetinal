#!/usr/bin/env python3
"""
Unit tests for Demon Sniffer v2.0
Run: python test_demon_sniffer_v2.py
No root required — tests only parse + logic layers, never open raw sockets.
"""

import struct
import socket
import time
import unittest
from netsentinel import (
    IPHeader, TCPHeader, UDPHeader, ICMPHeader,
    Packet, PacketParser, DisplayFilter,
    ThreatDetector, Stats, ThreatEvent,
    SYN_FLOOD_THRESHOLD, PORT_SCAN_THRESHOLD,
)


# ──────────────────────────────────────────────────────────────────────────────
# Helpers to build synthetic raw packets
# ──────────────────────────────────────────────────────────────────────────────

def make_ip_bytes(proto: int, src: str = "10.0.0.1", dst: str = "10.0.0.2",
                  total_len: int = 40, ttl: int = 64) -> bytes:
    """Return a minimal 20-byte IP header."""
    src_b = socket.inet_aton(src)
    dst_b = socket.inet_aton(dst)
    return struct.pack(
        "!BBHHHBBH4s4s",
        0x45,           # ver=4, ihl=5
        0,              # TOS
        total_len,
        0,              # identification
        0,              # flags + fragment
        ttl,
        proto,
        0,              # checksum (not verified in parser)
        src_b, dst_b,
    )

def make_tcp_bytes(sport: int = 1234, dport: int = 80,
                   flags: int = 0x02) -> bytes:
    """Return a 20-byte TCP header."""
    return struct.pack(
        "!HHLLBBHHH",
        sport, dport,
        0,              # seq
        0,              # ack
        0x50,           # data offset = 5 (20 bytes), reserved
        flags,
        65535,          # window
        0,              # checksum
        0,              # urgent
    )

def make_udp_bytes(sport: int = 5000, dport: int = 53) -> bytes:
    return struct.pack("!HHHH", sport, dport, 8, 0)

def make_icmp_bytes(icmp_type: int = 8, code: int = 0) -> bytes:
    return struct.pack("!BBHi", icmp_type, code, 0, 0)

def build_raw_tcp(src="10.0.0.1", dst="10.0.0.2", sport=1234, dport=80,
                  flags=0x02, ttl=64) -> bytes:
    ip  = make_ip_bytes(proto=6, src=src, dst=dst, total_len=40, ttl=ttl)
    tcp = make_tcp_bytes(sport=sport, dport=dport, flags=flags)
    return ip + tcp

def build_raw_udp(src="10.0.0.1", dst="10.0.0.2", sport=5000, dport=53) -> bytes:
    ip  = make_ip_bytes(proto=17, src=src, dst=dst, total_len=28)
    udp = make_udp_bytes(sport=sport, dport=dport)
    return ip + udp

def build_raw_icmp(src="10.0.0.1", dst="10.0.0.2", icmp_type=8) -> bytes:
    ip   = make_ip_bytes(proto=1, src=src, dst=dst, total_len=28)
    icmp = make_icmp_bytes(icmp_type=icmp_type)
    return ip + icmp


# ──────────────────────────────────────────────────────────────────────────────
# Tests
# ──────────────────────────────────────────────────────────────────────────────

class TestIPHeaderParsing(unittest.TestCase):

    def test_basic_fields(self):
        raw = make_ip_bytes(proto=6, src="192.168.1.10", dst="10.0.0.1", ttl=128)
        ip = IPHeader.parse(raw)
        self.assertEqual(ip.version, 4)
        self.assertEqual(ip.ihl, 20)
        self.assertEqual(ip.protocol, 6)
        self.assertEqual(ip.src_ip, "192.168.1.10")
        self.assertEqual(ip.dst_ip, "10.0.0.1")
        self.assertEqual(ip.ttl, 128)

    def test_too_short_raises(self):
        with self.assertRaises(struct.error):
            IPHeader.parse(b"\x00" * 10)


class TestTCPHeaderParsing(unittest.TestCase):

    def test_syn_flag(self):
        raw = make_tcp_bytes(sport=1111, dport=443, flags=0x02)  # SYN
        tcp = TCPHeader.parse(raw)
        self.assertTrue(tcp.flag_syn)
        self.assertFalse(tcp.flag_ack)
        self.assertEqual(tcp.src_port, 1111)
        self.assertEqual(tcp.dst_port, 443)

    def test_syn_ack_flags(self):
        raw = make_tcp_bytes(flags=0x12)   # SYN + ACK
        tcp = TCPHeader.parse(raw)
        self.assertTrue(tcp.flag_syn)
        self.assertTrue(tcp.flag_ack)

    def test_service_lookup(self):
        raw = make_tcp_bytes(dport=80)
        tcp = TCPHeader.parse(raw)
        self.assertEqual(tcp.service, "HTTP")

    def test_unknown_service(self):
        raw = make_tcp_bytes(dport=19999)
        tcp = TCPHeader.parse(raw)
        self.assertEqual(tcp.service, "UNKNOWN")


class TestUDPHeaderParsing(unittest.TestCase):

    def test_dns_service(self):
        raw = make_udp_bytes(dport=53)
        udp = UDPHeader.parse(raw)
        self.assertEqual(udp.dst_port, 53)
        self.assertEqual(udp.service, "DNS")


class TestICMPHeaderParsing(unittest.TestCase):

    def test_echo_request(self):
        raw = make_icmp_bytes(icmp_type=8)
        icmp = ICMPHeader.parse(raw)
        self.assertEqual(icmp.icmp_type, 8)
        self.assertEqual(icmp.type_name, "Echo Request")

    def test_echo_reply(self):
        raw = make_icmp_bytes(icmp_type=0)
        icmp = ICMPHeader.parse(raw)
        self.assertEqual(icmp.type_name, "Echo Reply")


class TestPacketParser(unittest.TestCase):

    def test_parse_tcp(self):
        pkt = PacketParser.parse(build_raw_tcp(dport=80))
        self.assertIsNotNone(pkt)
        self.assertEqual(pkt.proto_name, "TCP")
        self.assertEqual(pkt.dst_port, 80)
        self.assertIsNone(pkt.udp)
        self.assertIsNone(pkt.icmp)

    def test_parse_udp(self):
        pkt = PacketParser.parse(build_raw_udp(dport=53))
        self.assertIsNotNone(pkt)
        self.assertEqual(pkt.proto_name, "UDP")
        self.assertEqual(pkt.dst_port, 53)

    def test_parse_icmp(self):
        pkt = PacketParser.parse(build_raw_icmp(icmp_type=8))
        self.assertIsNotNone(pkt)
        self.assertEqual(pkt.proto_name, "ICMP")
        self.assertEqual(pkt.icmp.type_name, "Echo Request")

    def test_too_short_returns_none(self):
        self.assertIsNone(PacketParser.parse(b"\x00" * 5))

    def test_to_dict_has_required_keys(self):
        pkt = PacketParser.parse(build_raw_tcp())
        d = pkt.to_dict()
        for key in ("timestamp", "protocol", "src_ip", "dst_ip", "ttl", "length"):
            self.assertIn(key, d)


class TestDisplayFilter(unittest.TestCase):

    def _tcp_pkt(self, src="10.0.0.1", dst="10.0.0.2", dport=80, flags=0x02):
        return PacketParser.parse(build_raw_tcp(src=src, dst=dst, dport=dport, flags=flags))

    def _udp_pkt(self):
        return PacketParser.parse(build_raw_udp())

    def test_empty_filter_matches_all(self):
        f = DisplayFilter("")
        self.assertTrue(f.match(self._tcp_pkt()))
        self.assertTrue(f.match(self._udp_pkt()))

    def test_proto_filter_tcp(self):
        f = DisplayFilter("proto=TCP")
        self.assertTrue(f.match(self._tcp_pkt()))
        self.assertFalse(f.match(self._udp_pkt()))

    def test_proto_filter_udp(self):
        f = DisplayFilter("proto=UDP")
        self.assertFalse(f.match(self._tcp_pkt()))
        self.assertTrue(f.match(self._udp_pkt()))

    def test_src_filter(self):
        f = DisplayFilter("src=10.0.0.1")
        self.assertTrue(f.match(self._tcp_pkt(src="10.0.0.1")))
        self.assertFalse(f.match(self._tcp_pkt(src="10.0.0.99")))

    def test_port_filter(self):
        f = DisplayFilter("port=80")
        self.assertTrue(f.match(self._tcp_pkt(dport=80)))
        self.assertFalse(f.match(self._tcp_pkt(dport=443)))

    def test_flags_filter_syn(self):
        f = DisplayFilter("flags=SYN")
        syn_pkt  = self._tcp_pkt(flags=0x02)   # SYN only
        ack_pkt  = self._tcp_pkt(flags=0x10)   # ACK only
        self.assertTrue(f.match(syn_pkt))
        self.assertFalse(f.match(ack_pkt))

    def test_combined_filter(self):
        f = DisplayFilter("proto=TCP port=443")
        self.assertTrue(f.match(self._tcp_pkt(dport=443)))
        self.assertFalse(f.match(self._tcp_pkt(dport=80)))
        self.assertFalse(f.match(self._udp_pkt()))


class TestThreatDetector(unittest.TestCase):

    def _syn_pkt(self, src: str = "10.0.0.1") -> Packet:
        return PacketParser.parse(build_raw_tcp(src=src, flags=0x02))  # SYN

    def _udp_dns_pkt(self, src: str = "10.0.0.1") -> Packet:
        return PacketParser.parse(build_raw_udp(src=src, dport=53))

    def test_syn_flood_triggered(self):
        det = ThreatDetector()
        events = []
        pkt = self._syn_pkt("1.2.3.4")
        for _ in range(SYN_FLOOD_THRESHOLD + 5):
            events.extend(det.analyze(pkt))
        kinds = [e.kind for e in events]
        self.assertIn("SYN_FLOOD", kinds)

    def test_syn_flood_not_triggered_below_threshold(self):
        det = ThreatDetector()
        pkt = self._syn_pkt("1.2.3.5")
        events = []
        for _ in range(SYN_FLOOD_THRESHOLD - 1):
            events.extend(det.analyze(pkt))
        self.assertEqual(events, [])

    def test_port_scan_triggered(self):
        det = ThreatDetector()
        events = []
        src_ip = "1.2.3.6"
        for port in range(PORT_SCAN_THRESHOLD + 5):
            pkt = PacketParser.parse(build_raw_tcp(src=src_ip, dport=port + 1024))
            if pkt:
                events.extend(det.analyze(pkt))
        kinds = [e.kind for e in events]
        self.assertIn("PORT_SCAN", kinds)

    def test_dns_flood_triggered(self):
        from netsentinel import DNS_TUNNEL_THRESHOLD
        det = ThreatDetector()
        pkt = self._udp_dns_pkt("1.2.3.7")
        events = []
        for _ in range(DNS_TUNNEL_THRESHOLD + 5):
            events.extend(det.analyze(pkt))
        kinds = [e.kind for e in events]
        self.assertIn("DNS_TUNNEL", kinds)


class TestStats(unittest.TestCase):

    def test_accumulates_correctly(self):
        stats = Stats()
        pkt1 = PacketParser.parse(build_raw_tcp())
        pkt2 = PacketParser.parse(build_raw_udp())
        stats.record(pkt1)
        stats.record(pkt2)
        s = stats.summary()
        self.assertEqual(s["total_packets"], 2)
        self.assertIn("TCP", s["by_protocol"])
        self.assertIn("UDP", s["by_protocol"])

    def test_threat_count(self):
        stats = Stats()
        stats.record_threat(ThreatEvent("SYN_FLOOD", "1.2.3.4", "test"))
        self.assertEqual(stats.summary()["threat_count"], 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
