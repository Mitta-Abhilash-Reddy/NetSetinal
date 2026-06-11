# NetSentinel 🛡️

**Multi-protocol network packet analyzer with real-time threat detection**

NetSentinel captures and dissects live network traffic at the raw socket level — parsing TCP, UDP, and ICMP packets, detecting active threats (SYN floods, port scans, DNS tunneling), and logging structured telemetry. Built in pure Python with zero external dependencies.


---

## Features

| Category | What it does |
|---|---|
| **Protocol analysis** | Full TCP/UDP/ICMP header parsing — flags, ports, TTL, service identification |
| **Threat detection** | Real-time SYN flood, port scan, and DNS tunneling alerts with sliding-window counters |
| **Display filters** | BPF-inspired filters: `proto=TCP port=443 src=10.0.0.1 flags=SYN` |
| **Structured logging** | JSON-lines output with automatic size-based log rotation |
| **Live statistics** | Packets/sec, bits/sec, top talkers, protocol breakdown, threat count |
| **Graceful shutdown** | SIGINT/SIGTERM handling, privilege validation, clean socket teardown |
| **Test suite** | 27 unit tests — all pass without root, covering parsing, filtering, and detection |

---

## Quick Start

> **Requires root/administrator** — raw sockets need elevated privileges for capture. Tests do not.

```bash
# Clone
git clone https://github.com/YOUR_USERNAME/NetSentinel.git
cd NetSentinel

# Run tests (no root needed)
python test_netsentinel.py

# Capture all traffic on all interfaces
sudo python netsentinel.py

# Capture with a display filter
sudo python netsentinel.py --host 0.0.0.0 --filter "proto=TCP port=80"

# Filter for only SYN packets (connection attempts)
sudo python netsentinel.py --filter "flags=SYN" --verbose

# Log to file + print stats every 5 seconds
sudo python netsentinel.py --log capture.jsonl --stats-interval 5

# Disable threat detection (pure capture mode)
sudo python netsentinel.py --no-threats
```

### Windows

```cmd
# Run as Administrator in Command Prompt
python netsentinel.py --host 0.0.0.0
```

---

## Sample Output

```
Demon Sniffer v2.0  |  host=0.0.0.0  |  threats=on  |  log=none
Filter: none
────────────────────────────────────────────────────────────

14:22:01.483  TCP   192.168.1.5      → 142.250.80.46    :54321 → :443 [HTTPS] [S]  TTL=64  len=60
14:22:01.484  TCP   142.250.80.46    → 192.168.1.5      :443 → :54321 [HTTPS] [S/A] TTL=118 len=60
14:22:01.501  UDP   192.168.1.5      → 8.8.8.8          :55301 → :53 [DNS]          TTL=64  len=72
14:22:01.510  ICMP  192.168.1.5      → 8.8.8.8          Echo Request  TTL=64  len=84

⚠  THREAT  SYN_FLOOD @ 14:22:03: 103 SYN/s from 10.0.0.44

────────────────────────────────────────────────────────────
  Packets : 1247  |  Bytes: 892430  |  Rate: 89.1 pps / 642.5 kbps
  Protocols: {'TCP': 891, 'UDP': 312, 'ICMP': 44}
  Top sources: [('192.168.1.5', 743), ('10.0.0.44', 312)]
  Top services: [('HTTPS', 540), ('DNS', 189), ('HTTP', 122)]
  Threats detected: 1
────────────────────────────────────────────────────────────
```

---

## CLI Reference

```
usage: netsentinel [--host IP] [--filter EXPR] [--verbose] [--log FILE]
                   [--stats-interval SEC] [--no-threats] [--no-color]

Options:
  --host IP             Bind to interface IP (default: 0.0.0.0 = all)
  --filter EXPR         Display filter expression (see below)
  --verbose, -v         Full packet details + hex dump
  --log FILE            Append packets as JSON-lines to FILE
  --stats-interval SEC  Stats summary every N seconds (default: 10)
  --no-threats          Disable threat detection engine
  --no-color            Disable ANSI color output
```

### Filter syntax

Conditions are space-separated and AND-ed together:

| Key | Values | Example |
|---|---|---|
| `proto` | `TCP`, `UDP`, `ICMP` | `proto=UDP` |
| `src` | IP address | `src=192.168.1.1` |
| `dst` | IP address | `dst=8.8.8.8` |
| `port` | Port number | `port=443` |
| `flags` | `SYN`, `ACK`, `FIN`, `RST` | `flags=SYN` |

Example: `proto=TCP port=80 src=192.168.1.5`

---

## Threat Detection

NetSentinel uses **sliding 1-second windows** per source IP to detect:

| Threat | Trigger | Default threshold |
|---|---|---|
| SYN Flood | Bare SYN packets (no ACK) from one source | 100 SYN/s |
| Port Scan | Distinct destination ports from one source | 20 ports/s |
| DNS Tunneling | DNS queries (UDP port 53) from one source | 50 queries/s |

Alerts include a 5-second cooldown per source to prevent log flooding.

---

## Architecture

```
netsentinel.py
├── IPHeader        — IP header parser (struct.unpack)
├── TCPHeader       — TCP header + flag accessors + service lookup
├── UDPHeader       — UDP header + service lookup
├── ICMPHeader      — ICMP type/code + human-readable name
├── Packet          — Assembled packet with unified accessors
├── PacketParser    — Stateless parse() factory (unit-testable, no I/O)
├── DisplayFilter   — BPF-style expression parser and matcher
├── ThreatDetector  — Sliding-window anomaly detector (thread-safe)
├── Stats           — Thread-safe statistics accumulator
├── JSONLogger      — Append-only JSON-lines logger with rotation
├── PacketPrinter   — Colored console output
└── DemonSniffer    — Orchestrator: socket lifecycle + capture loop
```

---

## Running Tests

```bash
python test_netsentinel.py -v
```

```
test_combined_filter ... ok
test_empty_filter_matches_all ... ok
test_flags_filter_syn ... ok
...
test_syn_flood_triggered ... ok
test_dns_flood_triggered ... ok
----------------------------------------------------------------------
Ran 27 tests in 0.004s
OK
```

Test coverage spans: IP/TCP/UDP/ICMP parsing, display filter logic, threat detection thresholds, statistics accumulation, and `Packet.to_dict()` serialization.

---

## Requirements

- Python 3.8+
- No external packages — stdlib only (`socket`, `struct`, `threading`, `json`, `argparse`, `signal`)
- Root/administrator for live capture (tests run without)

---

## Project Structure

```
NetSentinel/
├── netsentinel.py              # Main analyzer (v2)
├── test_netsentinel.py         # 27 unit tests
├── demon_sniffer_v1_original.py  # Original Demon-Sniffer (reference)
├── requirements.txt            # No external deps — stdlib only
├── README.md
└── PROJECT_DEEP_DIVE.md        # Architecture, design decisions, implementation detail
```

---



## License

MIT
