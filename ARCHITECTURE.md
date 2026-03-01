# DPI Engine – Complete Architecture Guide

> **Version 3.0** | Pure C++17 | Zero external dependencies | Windows / Linux / macOS

---

## Table of Contents

1. [What is DPI?](#1-what-is-dpi)  
2. [System Overview](#2-system-overview)  
3. [File Structure](#3-file-structure)  
4. [Packet Lifecycle](#4-packet-lifecycle)  
5. [Data Structures](#5-data-structures)  
6. [Component Deep Dives](#6-component-deep-dives)  
   - [PCAP Reader](#61-pcap-reader)  
   - [Packet Parser](#62-packet-parser)  
   - [SNI Extractor](#63-sni-extractor)  
   - [HTTP / DNS Extractors](#64-http--dns-extractors)  
   - [Connection Tracker](#65-connection-tracker)  
   - [Rule Manager](#66-rule-manager)  
   - [Fast Path Processor](#67-fast-path-processor)  
   - [Load Balancer](#68-load-balancer)  
7. [Multi-threaded Architecture](#7-multi-threaded-architecture)  
8. [New Features (v3.0)](#8-new-features-v30)  
9. [Build & Run Guide](#9-build--run-guide)  
10. [Performance & Tuning](#10-performance--tuning)

---

## 1. What is DPI?

**Deep Packet Inspection (DPI)** examines the actual *content* of network packets, not just their headers. Traditional firewalls only see source/destination IPs and ports. DPI looks inside the payload to answer:

- *Which application is generating this traffic?* (YouTube, TikTok, Zoom…)
- *Which exact server is the client connecting to?* (via SNI domain name)
- *Which browser/OS/library is this?* (via TLS JA3 fingerprint)
- *Should this connection be blocked?*

```
 Traditional Firewall:              DPI Engine:
 ┌─────────────────────┐            ┌─────────────────────────────────┐
 │ src: 192.168.1.5    │   block?   │ src: 192.168.1.5                │
 │ dst: 142.250.80.46  │ ─────────► │ dst: 142.250.80.46              │
 │ port: 443           │            │ port: 443  → TLS → youtube.com  │
 └─────────────────────┘            │ JA3: a7c...  → Chrome/Win       │
                                    │ Action: BLOCK (YouYube rule)    │
                                    └─────────────────────────────────┘
```

---

## 2. System Overview

```
                          ┌─────────────────────────────────────┐
   input.pcap  ──────────►│           DPI ENGINE v3.0           │──────────► output.pcap
                          │                                      │
                          │  ┌────────────┐  ┌──────────────┐  │──────────► report.json
                          │  │ PcapReader │  │ PacketParser │  │
                          │  └─────┬──────┘  └──────┬───────┘  │──────────► flows.csv
                          │        │                 │          │
                          │  ┌─────▼─────────────────▼──────┐  │
                          │  │       Processing Pipeline     │  │
                          │  │                               │  │
                          │  │  SNI Extract (TLS port 443)  │  │
                          │  │  HTTP Extract (port 80)       │  │
                          │  │  DNS Correlation (port 53)    │  │
                          │  │  JA3 Fingerprint              │  │
                          │  │  Port-based Protocol Label    │  │
                          │  │  Blocking Rule Check          │  │
                          │  └───────────────────────────────┘  │
                          │                                      │
                          │  ┌──────────────────────────────┐   │
                          │  │        Rule Manager          │   │
                          │  │  ┌──────┐ ┌─────┐ ┌──────┐  │   │
                          │  │  │  IP  │ │ App │ │Domain│  │   │
                          │  │  └──────┘ └─────┘ └──────┘  │   │
                          │  └──────────────────────────────┘   │
                          └─────────────────────────────────────┘
```

---

## 3. File Structure

```
Packet_analyzer-main/
│
├── include/                     ← Header files (API declarations)
│   ├── platform.h               ← Portable byte-order (ntohs/ntohl)
│   ├── pcap_reader.h            ← PCAP global/packet headers + reader class
│   ├── packet_parser.h          ← Ethernet/IP/TCP/UDP + ParsedPacket struct
│   ├── sni_extractor.h          ← TLS, HTTP, DNS, QUIC extractors
│   ├── types.h                  ← FiveTuple, AppType, Connection, DPIStats
│   ├── connection_tracker.h     ← Per-FP flow table with LRU eviction
│   ├── rule_manager.h           ← IP/App/Domain/Port blocking + persistence
│   ├── fast_path.h              ← FastPathProcessor + FPManager
│   ├── load_balancer.h          ← LoadBalancer thread
│   ├── thread_safe_queue.h      ← TSQueue<T> with condition variables
│   └── dpi_engine.h             ← Top-level orchestrator header
│
├── src/                         ← Implementation files
│   ├── types.cpp                ← appTypeToString(), sniToAppType()
│   ├── pcap_reader.cpp          ← Binary PCAP reading + byte-swap
│   ├── packet_parser.cpp        ← Ethernet/IP/TCP/UDP header parsing
│   ├── sni_extractor.cpp        ← TLS Client Hello → SNI; HTTP Host; DNS
│   ├── connection_tracker.cpp   ← Flow lifecycle management
│   ├── rule_manager.cpp         ← Rule storage, wildcard matching, save/load
│   ├── fast_path.cpp            ← Packet processing, inspection, blocking
│   ├── main_working.cpp  ★      ← SIMPLE version (single-threaded, v3.0)
│   └── dpi_mt.cpp        ★      ← MULTI-THREADED version
│
├── test_dpi.pcap                ← Sample capture for testing
├── generate_test_pcap.py        ← Generate synthetic test data
├── CMakeLists.txt               ← CMake build (builds dpi_working + dpi_engine)
├── build.bat                    ← Windows one-click build script
├── ARCHITECTURE.md              ← This document
└── README.md                    ← Original project documentation
```

---

## 4. Packet Lifecycle

Every packet travels this exact pipeline:

```
PCAP File
    │
    │  PcapReader::readNextPacket()
    ▼
RawPacket { header.ts_sec, header.ts_usec, header.incl_len, data[] }
    │
    │  PacketParser::parse()
    ▼
ParsedPacket { src_ip, dst_ip, src_port, dst_port, protocol,
               tcp_flags, has_tcp, has_udp, payload_data, ... }
    │
    │  Build FiveTuple { src_ip(u32), dst_ip(u32), src_port, dst_port, protocol }
    ▼
Flow& flow = flows[tuple]   ← hash map lookup / create
    │
    │  payload_offset calculation:
    │   14 (Ethernet) + ip_header_len + tcp_header_len
    ▼
Payload pointer + length
    │
    ├── Port 443 (HTTPS)?
    │       └── SNIExtractor::extract()   → "www.youtube.com"
    │       └── extractJA3()              → "772,49195-49199-...,0-23-..."  (Feature 2)
    │
    ├── Port 80 (HTTP)?
    │       └── HTTPHostExtractor::extract() → "example.com"
    │
    ├── Port 53 (DNS)?
    │       └── DNSExtractor::extractQuery() → "api.tiktok.com"
    │       └── dns_corr.recordDNSQuery()    (Feature 3 – store for correlation)
    │
    ├── Other ports?
    │       └── portToProtocolLabel(dst_port) → "SSH", "RDP", "MySQL" ... (Feature 1)
    │       └── portToAppType(dst_port)       → AppType::TLS, HTTP, ...
    │
    ├── Still UNKNOWN + port 443?
    │       └── dns_corr.correlate(src_ip) → domain from recent DNS (Feature 3)
    │
    ▼
sniToAppType(sni) → AppType::YOUTUBE / FACEBOOK / TIKTOK / ...
    │
    ▼
rules.isBlocked(src_ip, dst_port, app_type, sni)?
    │
    ├── YES → dropped++   (packet NOT written to output)
    └── NO  → forwarded++ → write PcapPacketHeader + data to output.pcap
    │
    ▼  (after all packets processed)
Print report → export JSON (Feature 5) → export CSV (Feature 6)
```

---

## 5. Data Structures

### FiveTuple — Connection Identity Key

```cpp
struct FiveTuple {
    uint32_t src_ip;    // 4-byte source IP      e.g. 0xC0A80164 = 192.168.1.100
    uint32_t dst_ip;    // 4-byte destination IP
    uint16_t src_port;  // TCP/UDP source port
    uint16_t dst_port;  // TCP/UDP destination port
    uint8_t  protocol;  // IPPROTO_TCP=6, IPPROTO_UDP=17
};
```

A custom hash is used to put `FiveTuple` into `std::unordered_map`:
```cpp
struct FiveTupleHash {
    size_t operator()(const FiveTuple& t) const {
        // Boost-style hash combining all 5 fields
    }
};
```

### AppType — Application Classification

```
AppType::UNKNOWN    – not yet identified
AppType::HTTP       – port 80 without a recognized Host
AppType::HTTPS      – port 443 without a recognized SNI
AppType::DNS        – port 53 traffic
AppType::TLS        – TLS on non-standard port (SSH, SMTPS…)
AppType::GOOGLE     – *.google.com, gstatic.com, …
AppType::YOUTUBE    – *.youtube.com, ytimg.com, …
AppType::FACEBOOK   – facebook.com, fbcdn.net, meta.com, …
AppType::INSTAGRAM  – instagram.com, cdninstagram.com
AppType::NETFLIX    – netflix.com, nflxvideo.net, …
AppType::AMAZON     – amazon.com, amazonaws.com, cloudfront.net
AppType::MICROSOFT  – microsoft.com, azure.com, live.com, bing.com
AppType::APPLE      – apple.com, icloud.com, itunes.com
AppType::TIKTOK     – tiktok.com, tiktokcdn.com, bytedance.com
AppType::DISCORD    – discord.com, discordapp.com
AppType::GITHUB     – github.com, githubusercontent.com
AppType::ZOOM       – zoom.us
AppType::SPOTIFY    – spotify.com, scdn.co
AppType::WHATSAPP   – whatsapp.com
AppType::TELEGRAM   – telegram.org, t.me
AppType::TWITTER    – twitter.com, x.com, twimg.com
AppType::CLOUDFLARE – cloudflare.com, 1.1.1.1
AppType::QUIC       – QUIC/HTTP3 (OpenVPN, WireGuard)
```

---

## 6. Component Deep Dives

### 6.1 PCAP Reader

**File:** `pcap_reader.h / pcap_reader.cpp`

A PCAP file starts with a 24-byte global header followed by packets, each with a 16-byte packet header:

```
PCAP File Layout:
┌─────────────────────────────────────────────┐
│ Global Header (24 bytes)                    │
│   magic: 0xa1b2c3d4  version: 2.4           │
│   thiszone: 0  sigfigs: 0                   │
│   snaplen: 65535  network: 1 (Ethernet)     │
├─────────────────────────────────────────────┤
│ Packet Header (16 bytes) ← per packet       │
│   ts_sec, ts_usec, incl_len, orig_len       │
├─────────────────────────────────────────────┤
│ Packet Data (incl_len bytes)                │
├─────────────────────────────────────────────┤
│  ... repeat ...                             │
└─────────────────────────────────────────────┘
```

**Key operations:**
- `open()` — reads and validates the magic number, detects byte order
- `readNextPacket()` — returns `RawPacket` with header + raw byte vector
- Auto byte-swap for big-endian PCAP files (`needs_byte_swap_`)

---

### 6.2 Packet Parser

**File:** `packet_parser.h / packet_parser.cpp`

Parses the layered headers from raw bytes:

```
raw.data bytes:
[0 – 13]   Ethernet Header (14 bytes)
              dst_mac[6] | src_mac[6] | ethertype[2]
[14 – 33]  IPv4 Header (20 bytes minimum)
              ver_ihl | tos | total_len | id | frag | ttl | proto | cksum | src_ip | dst_ip
[34 – 53]  TCP Header (20 bytes minimum)
              src_port | dst_port | seq | ack | offset_flags | window | cksum | urg
[54+]      Payload (TLS, HTTP, DNS data...)
```

> **ntohs / ntohl** — All multi-byte fields in network packets are big-endian.  
> `platform.h` provides portable `netToHost16()` / `netToHost32()` replacements.

---

### 6.3 SNI Extractor

**File:** `sni_extractor.h / sni_extractor.cpp`

The TLS Client Hello contains the SNI (Server Name Indication) in **plaintext**, exposing the domain even over HTTPS:

```
TCP Payload → TLS Client Hello:
Byte 0:      0x16  = Content-Type Handshake
Bytes 1-2:   0x0303 = TLS 1.2 (legacy version field)
Bytes 3-4:   Record length
Byte 5:      0x01  = Client Hello
Bytes 6-8:   Handshake length (24-bit)
Bytes 9-10:  Client version
Bytes 11-42: Random (32 bytes)
Byte 43:     Session ID length (N)
Bytes 44…:   Session ID (N bytes)
After:        Cipher Suites length + list
After:        Compression Methods
After:        Extensions total length
  ┌── Extension loop ──────────────────┐
  │ Type (2) | Length (2) | Data       │
  │ Type 0x0000 = SNI Extension!       │
  │   ├── SNI list length (2)          │
  │   ├── SNI type: 0x00 (hostname)    │
  │   ├── SNI length (2)               │
  │   └── SNI value: "www.youtube.com" │← EXTRACTED HERE
  └────────────────────────────────────┘
```

**Key function:** `SNIExtractor::extract(payload, length)` → `std::optional<std::string>`

---

### 6.4 HTTP / DNS Extractors

**HTTP Host Header** (port 80):
```
GET /index.html HTTP/1.1\r\n
Host: www.example.com\r\n      ← scanned byte-by-byte
...
```
`HTTPHostExtractor::extract()` scans for `Host:` (case-insensitive), extracts value, strips port.

**DNS Query** (port 53, UDP):
```
DNS Header (12 bytes):
  Transaction ID | Flags | QDCOUNT | ANCOUNT | NSCOUNT | ARCOUNT
Question section:
  Labels: 3 | api | 6 | tiktok | 3 | com | 0  → "api.tiktok.com"
  QTYPE | QCLASS
```
`DNSExtractor::extractQuery()` decodes the label encoding to a dot-separated domain name.

---

### 6.5 Connection Tracker

**File:** `connection_tracker.h / connection_tracker.cpp`

Maintains a per-FastPath flow table `unordered_map<FiveTuple, Connection>`:

```
ConnectionState machine:
  NEW ──SYN──► ESTABLISHED ──SNI found──► CLASSIFIED ──rule match──► BLOCKED
   └──RST──────────────────────────────────────────────────────────► CLOSED
   └──FIN+ACK──────────────────────────────────────────────────────► CLOSED
```

**LRU Eviction:** when the table exceeds `max_connections` (default 100,000), the connection with the oldest `last_seen` timestamp is dropped.

**Bidirectional Matching:** `getConnection()` also checks the reverse tuple `{dst,src}` so replies from servers update the same flow entry.

---

### 6.6 Rule Manager

**File:** `rule_manager.h / rule_manager.cpp`

Thread-safe rule storage using `std::shared_mutex` (readers don't block each other):

```
Priority (first match wins):
 1. IP Block     – exact source IP match
 2. Port Block   – destination port match
 3. App Block    – matched AppType (after SNI classification)
 4. Domain Block – substring OR wildcard (*.example.com) in SNI/Host
```

**Rule file format** (`.txt`):
```ini
[BLOCKED_IPS]
192.168.1.50

[BLOCKED_APPS]
YouTube
TikTok

[BLOCKED_DOMAINS]
*.tiktok.com
ads.

[BLOCKED_PORTS]
6881
```
Load with `--rules rules.txt`. Save by calling `RuleManager::saveRules()`.

---

### 6.7 Fast Path Processor

**File:** `fast_path.h / fast_path.cpp`

The core processing unit. Each FP thread:
1. Pops a `PacketJob` from its input `TSQueue`
2. Calls `getOrCreateConnection()` on its private flow table
3. Inspects payload: SNI → HTTP Host → DNS → port fallback
4. Checks rules → `DROP` or `FORWARD`
5. Calls `output_callback_` (write to output file)

Tracks per-FP counters: `packets_processed`, `sni_extractions`, `classification_hits`.

---

### 6.8 Load Balancer

**File:** `load_balancer.h`

Routes packets to FP threads using **consistent hashing** on the 5-tuple:

```cpp
size_t fp_idx = FiveTupleHash{}(pkt.tuple) % num_fps;
fps_[fp_idx]->queue().push(pkt);
```

Why consistent hashing? All packets of the same TCP connection always go to the **same FP thread**, so that thread's flow table has the complete state for that connection.

---

## 7. Multi-threaded Architecture

**File:** `dpi_mt.cpp`

```
                     ┌──────────────────────────┐
                     │       Reader Thread       │
                     │  PcapReader + PacketParser │
                     └──────────┬───────────────┘
                                │ hash(5-tuple) % num_lbs
                    ┌───────────┴───────────┐
                    ▼                       ▼
            ┌──────────────┐       ┌──────────────┐
            │  LB Thread 0 │       │  LB Thread 1 │
            │  TSQueue     │       │  TSQueue     │
            └──────┬───────┘       └──────┬───────┘
                   │ hash % fps_per_lb     │
          ┌────────┴───────┐     ┌────────┴───────┐
          ▼                ▼     ▼                ▼
     ┌─────────┐    ┌─────────┐ ┌─────────┐ ┌─────────┐
     │  FP  0  │    │  FP  1  │ │  FP  2  │ │  FP  3  │
     │ flow tbl│    │ flow tbl│ │ flow tbl│ │ flow tbl│
     └────┬────┘    └────┬────┘ └────┬────┘ └────┬────┘
          └──────────────┴───────────┴────────────┘
                                │
                                ▼  TSQueue<Packet>
                    ┌───────────────────────────┐
                    │     Output Writer Thread   │
                    │  writes to output.pcap     │
                    └───────────────────────────┘
```

**Thread-Safe Queue** (`thread_safe_queue.h`):
```cpp
template<typename T>
class TSQueue {
    std::queue<T>            queue_;
    std::mutex               mutex_;
    std::condition_variable  not_empty_, not_full_;
    std::atomic<bool>        shutdown_;
    // push() signals not_empty_
    // pop() waits on not_empty_, signals not_full_
};
```

**Shutdown sequence:**
1. Reader finishes → sleeps 500ms for queues to drain
2. Stops all LBs → LB queues shutdown
3. Stops all FPs → FP queues shutdown
4. Signals output thread → drains remaining output queue
5. Output thread joins → file closed

---

## 8. New Features (v3.0)

### Feature 1 – Extended Protocol Detection

26 well-known ports mapped to labels. When SNI is unavailable:
```
Port 22  → SSH      Port 3389 → RDP      Port 6379 → Redis
Port 25  → SMTP     Port 5432 → PostgreSQL  Port 27017 → MongoDB
Port 587 → SMTP-TLS Port 3306 → MySQL     Port 51820 → WireGuard
```

### Feature 2 – TLS JA3 Fingerprinting

Extracts from TLS Client Hello:
- **TLS version** (e.g., 772 = TLS 1.3)
- **Cipher suite list** (GREASE values filtered)
- **Extensions type list** (GREASE filtered)

Produces a JA3 string: `"772,49195-49199-49196-...,0-23-65281-..."`  
And a 32-char hex hash: `"a4856c..."`

Same JA3 = same TLS library implementation (Chrome, Firefox, curl, etc.)

### Feature 3 – DNS Query Correlation

When a DNS query is seen from `src_ip` for `api.tiktok.com`, that mapping is stored. Later, when an HTTPS flow from the same IP to port 443 has no SNI (e.g., resumed TLS session), the DNS history is used to fill in the domain name.

### Feature 4 – Top-N Flow Reporter

Sorts flows by byte count descending, displays the top N in a formatted table. Use `--top 5` to see the 5 heaviest flows.

### Feature 5 – JSON Export (`--export-json`)

Writes a complete machine-readable JSON report:
```json
{
  "generated": "2026-03-01T15:12:00",
  "summary": { "total_packets": 1024, "forwarded": 980, "dropped": 44 },
  "app_distribution": { "YouTube": 320, "TikTok": 180, ... },
  "flows": [
    { "src_ip": "192.168.1.5", "dst_port": 443, "sni": "www.youtube.com",
      "ja3": "a7c4b3...", "packets": 42, "bytes": 65535, "blocked": false }
  ]
}
```

### Feature 6 – CSV Export (`--export-csv`)

Writes a flat CSV file with one row per flow:
```csv
src_ip,dst_ip,src_port,dst_port,protocol,app,proto_label,sni,ja3,packets,bytes,blocked
192.168.1.5,142.250.80.46,54321,443,6,YouTube,HTTPS,www.youtube.com,a7c4...,42,65535,false
```

### Feature 7 – Config File (`--rules`)

Load blocking rules from a plain-text file (see Rule Manager section for format). Supports all four rule types: IP, App, Domain (with wildcards), Port.

---

## 9. Build & Run Guide

### Requirements

| Tool | Where to Get |
|------|-------------|
| MSYS2 | https://www.msys2.org |
| MinGW-w64 GCC | `pacman -S mingw-w64-x86_64-gcc` |

### Build

```cmd
REM Double-click build.bat  OR run from Command Prompt:
cd c:\path\to\Packet_analyzer-main
build.bat
```

This produces:
- `dpi_working.exe` — Single-threaded, all v3.0 features
- `dpi_engine.exe`  — Multi-threaded, higher throughput

### Usage Examples

```cmd
REM Basic analysis
dpi_working.exe capture.pcap output.pcap

REM Block YouTube and TikTok
dpi_working.exe capture.pcap output.pcap --block-app YouTube --block-app TikTok

REM Export full report as JSON + CSV
dpi_working.exe capture.pcap output.pcap --export-json report.json --export-csv flows.csv

REM Load rules from file + show top 10 flows
dpi_working.exe capture.pcap output.pcap --rules myrules.txt --top 10

REM Block a specific IP and a domain pattern
dpi_working.exe capture.pcap output.pcap --block-ip 192.168.1.50 --block-domain ads.

REM Block RDP port
dpi_working.exe capture.pcap output.pcap --block-port 3389

REM Quiet mode (only write output, no terminal output)
dpi_working.exe capture.pcap output.pcap --quiet

REM Multi-threaded with 4 FPs
dpi_engine.exe capture.pcap output.pcap --lbs 2 --fps 2
```

### Example rules.txt

```ini
[BLOCKED_IPS]
192.168.1.99

[BLOCKED_APPS]
TikTok
YouTube

[BLOCKED_DOMAINS]
ads.
*.doubleclick.net

[BLOCKED_PORTS]
6881
```

---

## 10. Performance & Tuning

| Scenario | Recommended Setup |
|----------|------------------|
| Development / Analysis | `dpi_working.exe` (simple, easy to debug) |
| ≤ 100 Mbps capture | `dpi_engine.exe --lbs 1 --fps 2` |
| 100–500 Mbps capture | `dpi_engine.exe --lbs 2 --fps 4` |
| 500 Mbps+ capture | `dpi_engine.exe --lbs 4 --fps 8` |

**Bottlenecks to know:**
- SNI extraction only fires on the **first packet** of a TLS flow (Client Hello)
- DNS correlation keeps at most 50 queries per source IP (capped)
- Flow table uses `unordered_map` — very fast O(1) average lookup
- JA3 fingerprinting reads the same Client Hello as SNI extraction (no double parse)
- Output file writing is the single-threaded bottleneck in `dpi_mt.cpp` (TSQueue serializes)

**Memory:**  
Each `Flow` struct ≈ 200 bytes. 1 million flows ≈ 200 MB RAM.  
`ConnectionTracker` default cap: 100,000 flows per FP thread (LRU evicts oldest).
