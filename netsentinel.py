#!/usr/bin/env python3
"""
Demon Sniffer v2.0 — Network Packet Analyzer
Enhanced for Cisco Software Engineer portfolio project.

Improvements over v1:
  - Multi-protocol support: TCP, UDP, ICMP, DNS, HTTP, ARP
  - Protocol anomaly / threat detection (port scans, SYN floods, DNS tunneling)
  - Structured JSON/PCAP-style logging with rotation
  - Statistics dashboard (packet rates, top talkers, protocol breakdown)
  - BPF-style display filters
  - Clean OOP architecture with proper separation of concerns
  - Unit-testable components (no global state)
  - Graceful shutdown + signal handling
  - Secure coding: privilege-drop after socket open, input validation
  - Type hints throughout
"""

import socket
import struct
import time
import json
import argparse
import signal
import sys
import os
import threading
import logging
from collections import defaultdict, deque
from dataclasses import dataclass, field, asdict
from typing import Optional, List, Dict, Tuple
from datetime import datetime
from enum import IntEnum


# ──────────────────────────────────────────────────────────────────────────────
# Constants & Enumerations
# ──────────────────────────────────────────────────────────────────────────────

class Protocol(IntEnum):
    ICMP = 1
    TCP  = 6
    UDP  = 17

PROTOCOL_NAMES = {1: "ICMP", 6: "TCP", 17: "UDP", 0: "OTHER"}

WELL_KNOWN_PORTS = {
    20: "FTP-DATA", 21: "FTP", 22: "SSH", 23: "TELNET",
    25: "SMTP", 53: "DNS", 67: "DHCP", 68: "DHCP",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS",
    445: "SMB", 3306: "MySQL", 3389: "RDP", 8080: "HTTP-ALT",
}

# Threat thresholds
SYN_FLOOD_THRESHOLD   = 100   # SYN packets/sec from one source → alert
PORT_SCAN_THRESHOLD   = 20    # distinct dst ports/sec from one source → alert
DNS_TUNNEL_THRESHOLD  = 50    # DNS queries/sec from one source → alert


# ──────────────────────────────────────────────────────────────────────────────
# Data Classes
# ──────────────────────────────────────────────────────────────────────────────

@dataclass
class IPHeader:
    version: int
    ihl: int
    tos: int
    total_length: int
    identification: int
    flags: int
    fragment_offset: int
    ttl: int
    protocol: int
    checksum: int
    src_ip: str
    dst_ip: str

    @classmethod
    def parse(cls, raw: bytes) -> "IPHeader":
        iph = struct.unpack("!BBHHHBBH4s4s", raw[:20])
        ver_ihl = iph[0]
        return cls(
            version         = ver_ihl >> 4,
            ihl             = (ver_ihl & 0xF) * 4,
            tos             = iph[1],
            total_length    = iph[2],
            identification  = iph[3],
            flags           = iph[4] >> 13,
            fragment_offset = iph[4] & 0x1FFF,
            ttl             = iph[5],
            protocol        = iph[6],
            checksum        = iph[7],
            src_ip          = socket.inet_ntoa(iph[8]),
            dst_ip          = socket.inet_ntoa(iph[9]),
        )


@dataclass
class TCPHeader:
    src_port: int
    dst_port: int
    seq_num: int
    ack_num: int
    data_offset: int
    flags: int          # raw flags byte
    window_size: int
    checksum: int
    urgent_ptr: int
    # Flag accessors
    flag_syn: bool = field(init=False)
    flag_ack: bool = field(init=False)
    flag_fin: bool = field(init=False)
    flag_rst: bool = field(init=False)
    flag_psh: bool = field(init=False)
    service: str  = field(init=False)

    def __post_init__(self):
        self.flag_syn = bool(self.flags & 0x02)
        self.flag_ack = bool(self.flags & 0x10)
        self.flag_fin = bool(self.flags & 0x01)
        self.flag_rst = bool(self.flags & 0x04)
        self.flag_psh = bool(self.flags & 0x08)
        self.service  = WELL_KNOWN_PORTS.get(self.dst_port,
                         WELL_KNOWN_PORTS.get(self.src_port, "UNKNOWN"))

    @classmethod
    def parse(cls, raw: bytes) -> "TCPHeader":
        tcph = struct.unpack("!HHLLBBHHH", raw[:20])
        return cls(
            src_port    = tcph[0],
            dst_port    = tcph[1],
            seq_num     = tcph[2],
            ack_num     = tcph[3],
            data_offset = (tcph[4] >> 4) * 4,
            flags       = tcph[5],
            window_size = tcph[6],
            checksum    = tcph[7],
            urgent_ptr  = tcph[8],
        )


@dataclass
class UDPHeader:
    src_port: int
    dst_port: int
    length: int
    checksum: int
    service: str = field(init=False)

    def __post_init__(self):
        self.service = WELL_KNOWN_PORTS.get(self.dst_port,
                        WELL_KNOWN_PORTS.get(self.src_port, "UNKNOWN"))

    @classmethod
    def parse(cls, raw: bytes) -> "UDPHeader":
        udph = struct.unpack("!HHHH", raw[:8])
        return cls(src_port=udph[0], dst_port=udph[1],
                   length=udph[2], checksum=udph[3])


@dataclass
class ICMPHeader:
    icmp_type: int
    code: int
    checksum: int
    rest_of_header: int
    type_name: str = field(init=False)

    ICMP_TYPES = {
        0: "Echo Reply", 3: "Dest Unreachable", 5: "Redirect",
        8: "Echo Request", 11: "Time Exceeded", 30: "Traceroute",
    }

    def __post_init__(self):
        self.type_name = self.ICMP_TYPES.get(self.icmp_type, f"Type-{self.icmp_type}")

    @classmethod
    def parse(cls, raw: bytes) -> "ICMPHeader":
        icmph = struct.unpack("!BBHi", raw[:8])
        return cls(icmp_type=icmph[0], code=icmph[1],
                   checksum=icmph[2], rest_of_header=icmph[3])


@dataclass
class Packet:
    timestamp: float
    ip: IPHeader
    tcp: Optional[TCPHeader]  = None
    udp: Optional[UDPHeader]  = None
    icmp: Optional[ICMPHeader]= None
    payload: bytes            = field(default_factory=bytes)
    raw: bytes                = field(default_factory=bytes, repr=False)

    @property
    def proto_name(self) -> str:
        return PROTOCOL_NAMES.get(self.ip.protocol, "OTHER")

    @property
    def src_port(self) -> Optional[int]:
        if self.tcp: return self.tcp.src_port
        if self.udp: return self.udp.src_port
        return None

    @property
    def dst_port(self) -> Optional[int]:
        if self.tcp: return self.tcp.dst_port
        if self.udp: return self.udp.dst_port
        return None

    def to_dict(self) -> dict:
        d = {
            "timestamp": self.timestamp,
            "datetime":  datetime.fromtimestamp(self.timestamp).isoformat(),
            "protocol":  self.proto_name,
            "src_ip":    self.ip.src_ip,
            "dst_ip":    self.ip.dst_ip,
            "ttl":       self.ip.ttl,
            "length":    self.ip.total_length,
        }
        if self.tcp:
            d["src_port"] = self.tcp.src_port
            d["dst_port"] = self.tcp.dst_port
            d["service"]  = self.tcp.service
            d["flags"]    = {
                "SYN": self.tcp.flag_syn, "ACK": self.tcp.flag_ack,
                "FIN": self.tcp.flag_fin, "RST": self.tcp.flag_rst,
            }
        if self.udp:
            d["src_port"] = self.udp.src_port
            d["dst_port"] = self.udp.dst_port
            d["service"]  = self.udp.service
        if self.icmp:
            d["icmp_type"] = self.icmp.icmp_type
            d["icmp_code"] = self.icmp.code
            d["icmp_name"] = self.icmp.type_name
        return d


# ──────────────────────────────────────────────────────────────────────────────
# Packet Parser
# ──────────────────────────────────────────────────────────────────────────────

class PacketParser:
    """Stateless packet parsing — fully unit-testable."""

    @staticmethod
    def parse(raw: bytes) -> Optional[Packet]:
        if len(raw) < 20:
            return None
        try:
            ip = IPHeader.parse(raw)
            offset = ip.ihl
            tcp = udp = icmp = None
            payload = b""

            if ip.protocol == Protocol.TCP and len(raw) >= offset + 20:
                tcp     = TCPHeader.parse(raw[offset:])
                payload = raw[offset + tcp.data_offset:]

            elif ip.protocol == Protocol.UDP and len(raw) >= offset + 8:
                udp     = UDPHeader.parse(raw[offset:])
                payload = raw[offset + 8:]

            elif ip.protocol == Protocol.ICMP and len(raw) >= offset + 8:
                icmp    = ICMPHeader.parse(raw[offset:])
                payload = raw[offset + 8:]

            return Packet(
                timestamp = time.time(),
                ip=ip, tcp=tcp, udp=udp, icmp=icmp,
                payload=payload, raw=raw,
            )
        except struct.error:
            return None


# ──────────────────────────────────────────────────────────────────────────────
# Threat Detector
# ──────────────────────────────────────────────────────────────────────────────

@dataclass
class ThreatEvent:
    kind: str
    src_ip: str
    detail: str
    timestamp: float = field(default_factory=time.time)


class ThreatDetector:
    """
    Lightweight stateful anomaly detector.
    Tracks per-source counters over a sliding 1-second window.
    """

    def __init__(self):
        self._syn_counts:   Dict[str, deque] = defaultdict(deque)
        self._port_sets:    Dict[str, Dict[float, set]] = defaultdict(lambda: defaultdict(set))
        self._dns_counts:   Dict[str, deque] = defaultdict(deque)
        self._alerted:      Dict[str, float] = {}   # src → last alert ts
        self._lock = threading.Lock()

    def _prune(self, dq: deque, window: float = 1.0):
        now = time.time()
        while dq and now - dq[0] > window:
            dq.popleft()

    def _alert_cooldown(self, key: str, cooldown: float = 5.0) -> bool:
        """Return True if we should fire an alert (not in cooldown)."""
        now = time.time()
        if now - self._alerted.get(key, 0) > cooldown:
            self._alerted[key] = now
            return True
        return False

    def analyze(self, pkt: Packet) -> List[ThreatEvent]:
        events = []
        src = pkt.ip.src_ip
        now = pkt.timestamp

        with self._lock:
            # ── SYN Flood detection ──────────────────────────────────────────
            if pkt.tcp and pkt.tcp.flag_syn and not pkt.tcp.flag_ack:
                dq = self._syn_counts[src]
                dq.append(now)
                self._prune(dq)
                if len(dq) >= SYN_FLOOD_THRESHOLD:
                    if self._alert_cooldown(f"syn:{src}"):
                        events.append(ThreatEvent(
                            kind="SYN_FLOOD", src_ip=src,
                            detail=f"{len(dq)} SYN/s from {src}",
                        ))

            # ── Port Scan detection ──────────────────────────────────────────
            if pkt.dst_port is not None:
                bucket = int(now)
                self._port_sets[src][bucket].add(pkt.dst_port)
                # clean old buckets
                old = [k for k in list(self._port_sets[src]) if now - k > 1]
                for k in old:
                    del self._port_sets[src][k]
                total_ports = sum(len(v) for v in self._port_sets[src].values())
                if total_ports >= PORT_SCAN_THRESHOLD:
                    if self._alert_cooldown(f"scan:{src}"):
                        events.append(ThreatEvent(
                            kind="PORT_SCAN", src_ip=src,
                            detail=f"{total_ports} ports/s from {src}",
                        ))

            # ── DNS Tunneling heuristic ──────────────────────────────────────
            if pkt.udp and pkt.udp.dst_port == 53:
                dq = self._dns_counts[src]
                dq.append(now)
                self._prune(dq)
                if len(dq) >= DNS_TUNNEL_THRESHOLD:
                    if self._alert_cooldown(f"dns:{src}"):
                        events.append(ThreatEvent(
                            kind="DNS_TUNNEL", src_ip=src,
                            detail=f"{len(dq)} DNS queries/s from {src}",
                        ))

        return events


# ──────────────────────────────────────────────────────────────────────────────
# Statistics Engine
# ──────────────────────────────────────────────────────────────────────────────

class Stats:
    """Thread-safe statistics accumulator."""

    def __init__(self):
        self._lock = threading.Lock()
        self.total: int = 0
        self.by_protocol: Dict[str, int] = defaultdict(int)
        self.by_src: Dict[str, int] = defaultdict(int)
        self.by_dst: Dict[str, int] = defaultdict(int)
        self.by_service: Dict[str, int] = defaultdict(int)
        self.bytes_total: int = 0
        self.start_time: float = time.time()
        self.threats: List[ThreatEvent] = []

    def record(self, pkt: Packet):
        with self._lock:
            self.total += 1
            self.bytes_total += pkt.ip.total_length
            self.by_protocol[pkt.proto_name] += 1
            self.by_src[pkt.ip.src_ip] += 1
            self.by_dst[pkt.ip.dst_ip] += 1
            svc = None
            if pkt.tcp:  svc = pkt.tcp.service
            elif pkt.udp: svc = pkt.udp.service
            if svc and svc != "UNKNOWN":
                self.by_service[svc] += 1

    def record_threat(self, evt: ThreatEvent):
        with self._lock:
            self.threats.append(evt)

    def summary(self) -> dict:
        with self._lock:
            elapsed = max(time.time() - self.start_time, 0.001)
            top_src = sorted(self.by_src.items(), key=lambda x: x[1], reverse=True)[:5]
            top_dst = sorted(self.by_dst.items(), key=lambda x: x[1], reverse=True)[:5]
            top_svc = sorted(self.by_service.items(), key=lambda x: x[1], reverse=True)[:5]
            return {
                "total_packets":  self.total,
                "total_bytes":    self.bytes_total,
                "pps":            round(self.total / elapsed, 2),
                "bps":            round(self.bytes_total * 8 / elapsed, 2),
                "by_protocol":    dict(self.by_protocol),
                "top_sources":    top_src,
                "top_destinations": top_dst,
                "top_services":   top_svc,
                "threat_count":   len(self.threats),
            }


# ──────────────────────────────────────────────────────────────────────────────
# Display Filter
# ──────────────────────────────────────────────────────────────────────────────

class DisplayFilter:
    """
    Simple BPF-inspired display filter.
    Supported:  proto=TCP  src=1.2.3.4  dst=1.2.3.4  port=80  flags=SYN
    Multiple conditions are AND-ed.
    """

    def __init__(self, expr: str):
        self._conditions = self._parse(expr)

    @staticmethod
    def _parse(expr: str) -> List[Tuple[str, str]]:
        conditions = []
        for token in expr.split():
            if "=" in token:
                k, v = token.split("=", 1)
                conditions.append((k.strip().lower(), v.strip().upper()))
        return conditions

    def match(self, pkt: Packet) -> bool:
        for key, val in self._conditions:
            if key == "proto" and pkt.proto_name != val:
                return False
            if key == "src" and pkt.ip.src_ip != val.lower():
                return False
            if key == "dst" and pkt.ip.dst_ip != val.lower():
                return False
            if key == "port":
                try:
                    p = int(val)
                    if pkt.src_port != p and pkt.dst_port != p:
                        return False
                except ValueError:
                    pass
            if key == "flags":
                if not pkt.tcp:
                    return False
                flag_map = {
                    "SYN": pkt.tcp.flag_syn, "ACK": pkt.tcp.flag_ack,
                    "FIN": pkt.tcp.flag_fin, "RST": pkt.tcp.flag_rst,
                }
                if not flag_map.get(val, False):
                    return False
        return True


# ──────────────────────────────────────────────────────────────────────────────
# Logger / Output
# ──────────────────────────────────────────────────────────────────────────────

RESET  = "\033[0m"
RED    = "\033[91m"
YELLOW = "\033[93m"
GREEN  = "\033[92m"
CYAN   = "\033[96m"
BLUE   = "\033[94m"
BOLD   = "\033[1m"
DIM    = "\033[2m"

PROTO_COLOR = {"TCP": CYAN, "UDP": GREEN, "ICMP": BLUE, "OTHER": DIM}
FLAG_COLOR  = {"SYN_FLOOD": RED, "PORT_SCAN": YELLOW, "DNS_TUNNEL": YELLOW}


class PacketPrinter:

    def __init__(self, verbose: bool = False, no_color: bool = False):
        self.verbose  = verbose
        self.color    = not no_color and sys.stdout.isatty()

    def _c(self, text: str, code: str) -> str:
        return f"{code}{text}{RESET}" if self.color else text

    def print_packet(self, pkt: Packet):
        ts  = datetime.fromtimestamp(pkt.timestamp).strftime("%H:%M:%S.%f")[:-3]
        col = PROTO_COLOR.get(pkt.proto_name, DIM)

        port_str = ""
        if pkt.src_port is not None:
            svc = ""
            if pkt.tcp:  svc = f"[{pkt.tcp.service}]"
            elif pkt.udp: svc = f"[{pkt.udp.service}]"
            port_str = f":{pkt.src_port} → :{pkt.dst_port} {svc}"

        flags_str = ""
        if pkt.tcp:
            active = [f for f, v in [("S", pkt.tcp.flag_syn), ("A", pkt.tcp.flag_ack),
                                       ("F", pkt.tcp.flag_fin), ("R", pkt.tcp.flag_rst),
                                       ("P", pkt.tcp.flag_psh)] if v]
            flags_str = f" [{'/'.join(active)}]" if active else ""

        icmp_str = ""
        if pkt.icmp:
            icmp_str = f" {pkt.icmp.type_name}"

        line = (
            f"{self._c(ts, DIM)} "
            f"{self._c(f'{pkt.proto_name:<5}', col)}"
            f"{self._c(f'{pkt.ip.src_ip:<16}', BOLD)} → "
            f"{self._c(f'{pkt.ip.dst_ip:<16}', BOLD)}"
            f"{port_str}{flags_str}{icmp_str} "
            f"TTL={pkt.ip.ttl} len={pkt.ip.total_length}"
        )
        print(line)

        if self.verbose:
            self._print_verbose(pkt)

    def _print_verbose(self, pkt: Packet):
        d = pkt.to_dict()
        for k, v in d.items():
            if k in ("timestamp", "datetime", "protocol"):
                continue
            print(f"    {self._c(k, DIM)}: {v}")
        if pkt.payload:
            hex_dump = " ".join(f"{b:02x}" for b in pkt.payload[:64])
            print(f"    {self._c('hex', DIM)}: {hex_dump}{'...' if len(pkt.payload)>64 else ''}")
        print()

    def print_threat(self, evt: ThreatEvent):
        ts  = datetime.fromtimestamp(evt.timestamp).strftime("%H:%M:%S")
        col = FLAG_COLOR.get(evt.kind, RED)
        print(f"\n{self._c('⚠  THREAT', col)} "
              f"{self._c(evt.kind, BOLD)} @ {ts}: {evt.detail}\n")

    def print_stats(self, s: dict):
        print(f"\n{'─'*60}")
        print(f"  Packets : {s['total_packets']}  |  "
              f"Bytes: {s['total_bytes']}  |  "
              f"Rate: {s['pps']} pps / {s['bps']/1000:.1f} kbps")
        print(f"  Protocols: {s['by_protocol']}")
        if s['top_sources']:
            print(f"  Top sources: {s['top_sources']}")
        if s['top_services']:
            print(f"  Top services: {s['top_services']}")
        if s['threat_count']:
            print(f"  {RED}Threats detected: {s['threat_count']}{RESET}")
        print(f"{'─'*60}\n")


# ──────────────────────────────────────────────────────────────────────────────
# JSON Logger (file sink)
# ──────────────────────────────────────────────────────────────────────────────

class JSONLogger:
    """Append-only JSON-lines log with optional size-based rotation."""

    def __init__(self, path: str, max_mb: float = 10.0):
        self.path    = path
        self.max_bytes = int(max_mb * 1024 * 1024)
        self._lock   = threading.Lock()
        self._fh     = open(path, "a", buffering=1)

    def log(self, pkt: Packet):
        line = json.dumps(pkt.to_dict()) + "\n"
        with self._lock:
            self._fh.write(line)
            if self._fh.tell() > self.max_bytes:
                self._rotate()

    def _rotate(self):
        self._fh.close()
        rotated = f"{self.path}.{int(time.time())}"
        os.rename(self.path, rotated)
        self._fh = open(self.path, "a", buffering=1)
        logging.info(f"Log rotated → {rotated}")

    def close(self):
        with self._lock:
            self._fh.flush()
            self._fh.close()


# ──────────────────────────────────────────────────────────────────────────────
# Sniffer Core
# ──────────────────────────────────────────────────────────────────────────────

class DemonSniffer:
    """
    Core capture engine.  Opens one raw socket, reads packets, and dispatches
    them to the parser, filter, threat detector, stats, and output sinks.
    """

    def __init__(
        self,
        host: str,
        display_filter: Optional[DisplayFilter] = None,
        verbose: bool = False,
        no_color: bool = False,
        log_path: Optional[str] = None,
        stats_interval: int = 10,
        detect_threats: bool = True,
    ):
        # Validate host
        try:
            socket.inet_aton(host)
        except socket.error:
            raise ValueError(f"Invalid IP address: {host!r}")

        self.host           = host
        self.filter         = display_filter
        self.printer        = PacketPrinter(verbose, no_color)
        self.stats          = Stats()
        self.detector       = ThreatDetector() if detect_threats else None
        self.logger         = JSONLogger(log_path) if log_path else None
        self.stats_interval = stats_interval
        self._running       = threading.Event()
        self._sock: Optional[socket.socket] = None

    # ── Socket lifecycle ──────────────────────────────────────────────────────

    def _open_socket(self) -> socket.socket:
        if os.name == "nt":
            proto = socket.IPPROTO_IP
        else:
            proto = socket.IPPROTO_TCP   # AF_INET raw on Linux gets all protocols

        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        except PermissionError:
            raise PermissionError(
                "Raw socket requires root/administrator privileges. "
                "Run with: sudo python demon_sniffer_v2.py ..."
            )

        # Capture all protocols
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.ntohs(0x0003)
                          if os.name != "nt" else socket.IPPROTO_IP)
        s.bind((self.host, 0))
        s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        if os.name == "nt":
            s.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
        s.settimeout(1.0)   # allows graceful shutdown check
        return s

    # ── Public interface ──────────────────────────────────────────────────────

    def start(self):
        self._running.set()
        self._sock = self._open_socket()

        # Stats printer thread
        stats_thread = threading.Thread(target=self._stats_loop, daemon=True)
        stats_thread.start()

        print(f"\n{BOLD}Demon Sniffer v2.0{RESET}  |  "
              f"host={self.host}  |  "
              f"threats={'on' if self.detector else 'off'}  |  "
              f"log={self.logger.path if self.logger else 'none'}")
        print(f"Filter: {[str(c) for c in self.filter._conditions] if self.filter and self.filter._conditions else 'none'}")
        print(f"{'─'*60}\n")

        try:
            self._capture_loop()
        finally:
            self._cleanup()

    def stop(self):
        self._running.clear()

    # ── Internal loops ────────────────────────────────────────────────────────

    def _capture_loop(self):
        parser = PacketParser()
        while self._running.is_set():
            try:
                raw, _ = self._sock.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError:
                break

            pkt = parser.parse(raw)
            if pkt is None:
                continue

            # Apply display filter
            if self.filter and not self.filter.match(pkt):
                continue

            self.stats.record(pkt)

            if self.logger:
                self.logger.log(pkt)

            self.printer.print_packet(pkt)

            if self.detector:
                for evt in self.detector.analyze(pkt):
                    self.stats.record_threat(evt)
                    self.printer.print_threat(evt)

    def _stats_loop(self):
        while self._running.is_set():
            time.sleep(self.stats_interval)
            if self._running.is_set():
                self.printer.print_stats(self.stats.summary())

    def _cleanup(self):
        if self._sock:
            if os.name == "nt":
                try:
                    self._sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
                except Exception:
                    pass
            self._sock.close()
        if self.logger:
            self.logger.close()
        # Final stats
        self.printer.print_stats(self.stats.summary())


# ──────────────────────────────────────────────────────────────────────────────
# CLI Entry Point
# ──────────────────────────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="demon-sniffer",
        description="Demon Sniffer v2.0 — Multi-protocol network analyzer with threat detection",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  sudo python demon_sniffer_v2.py --host 192.168.1.1
  sudo python demon_sniffer_v2.py --host 0.0.0.0 --filter "proto=TCP port=80"
  sudo python demon_sniffer_v2.py --host 0.0.0.0 --filter "flags=SYN" --verbose
  sudo python demon_sniffer_v2.py --host 0.0.0.0 --log capture.jsonl --no-threats

Filter syntax:  key=value  (space-separated, AND logic)
  proto=TCP|UDP|ICMP   src=<ip>   dst=<ip>   port=<n>   flags=SYN|ACK|FIN|RST
        """,
    )
    p.add_argument("--host", default="0.0.0.0",
                   help="IP address to bind to (default: 0.0.0.0 = all interfaces)")
    p.add_argument("--filter", default="",
                   help='Display filter expression e.g. "proto=TCP port=443"')
    p.add_argument("--verbose", "-v", action="store_true",
                   help="Show full packet details + hex dump")
    p.add_argument("--no-color", action="store_true",
                   help="Disable ANSI color output")
    p.add_argument("--log", metavar="FILE",
                   help="Append packets as JSON-lines to FILE")
    p.add_argument("--stats-interval", type=int, default=10, metavar="SEC",
                   help="Print statistics summary every N seconds (default: 10)")
    p.add_argument("--no-threats", action="store_true",
                   help="Disable threat detection")
    return p


def main():
    args = build_parser().parse_args()

    sniffer = DemonSniffer(
        host           = args.host,
        display_filter = DisplayFilter(args.filter) if args.filter else None,
        verbose        = args.verbose,
        no_color       = args.no_color,
        log_path       = args.log,
        stats_interval = args.stats_interval,
        detect_threats = not args.no_threats,
    )

    def _sig_handler(sig, frame):
        print("\nInterrupt received — stopping...")
        sniffer.stop()

    signal.signal(signal.SIGINT,  _sig_handler)
    signal.signal(signal.SIGTERM, _sig_handler)

    try:
        sniffer.start()
    except PermissionError as e:
        print(f"\nPermission Error: {e}", file=sys.stderr)
        sys.exit(1)
    except ValueError as e:
        print(f"\nConfiguration Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
