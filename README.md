# DPI Engine v4.0

> **Deep Packet Inspection** — Real-time network traffic analysis, application detection, threat monitoring, and flow blocking.  
> Pure C++17 · Zero external dependencies · Windows / Linux / macOS

---

## What is this?

The DPI Engine inspects network packets at the **payload level**, going far beyond IP/port filtering. It identifies *exactly* which application is talking — YouTube, TikTok, Facebook, Discord, Zoom — by reading the TLS Server Name Indication (SNI) field inside encrypted HTTPS traffic. It also fingerprints TLS clients (JA3), correlates DNS queries to flows, detects threats like port scans, and can export full reports.

```
 Normal Firewall:               DPI Engine:
 [src: 192.168.1.5]             [src: 192.168.1.5]
 [dst: 99.86.0.100:443]  ──►   [dst: www.tiktok.com (TikTok)]
 [  ?  block?         ]         [JA3: a7c4b3... → Chrome/Win]
                                [Action: BLOCKED]
```

---

## Quick Start

### 1. Build

```cmd
cd Packet_analyzer-main
build.bat
```

> **Requires:** [MSYS2](https://www.msys2.org/) with MinGW-w64  
> `pacman -S mingw-w64-x86_64-gcc`

Produces three executables:

| Executable | Purpose |
|---|---|
| `dpi_working.exe` | Offline PCAP file analysis |
| `dpi_engine.exe` | Multi-threaded offline PCAP analysis |
| `dpi_live.exe` | **Real-time live capture** from network interface |

### 2. Analyze a PCAP file

```cmd
dpi_working.exe capture.pcap output.pcap
```

### 3. Live capture (real-time)

```cmd
REM Must run as Administrator
dpi_live.exe
```

---

## Features

### Offline Analysis (`dpi_working.exe`)

| Feature | Flag | Description |
|---------|------|-------------|
| **App detection** | auto | Identifies 22+ apps from TLS SNI / HTTP Host |
| **Extended protocols** | auto | Labels 26 port-based protocols (SSH, RDP, MySQL, Redis…) |
| **TLS JA3 fingerprint** | auto | Identifies TLS client (browser/OS/library) |
| **DNS correlation** | auto | Links HTTPS flows to recent DNS queries |
| **Blocking** | `--block-*` | Block by IP, app, domain, or port |
| **Rules file** | `--rules file` | Load blocking rules from a `.txt` config |
| **Top-N flows** | `--top N` | Print top N flows ranked by bytes |
| **JSON export** | `--export-json file` | Full report in JSON format |
| **CSV export** | `--export-csv file` | Flow table as CSV |
| **Verbose / Quiet** | `--verbose / --quiet` | Control output detail |

#### Usage

```cmd
REM Basic analysis
dpi_working.exe input.pcap output.pcap

REM Block YouTube and TikTok
dpi_working.exe input.pcap output.pcap --block-app YouTube --block-app TikTok

REM Block a specific port (RDP)
dpi_working.exe input.pcap output.pcap --block-port 3389

REM Load rules from file
dpi_working.exe input.pcap output.pcap --rules rules.txt

REM Export full report + show top 10 flows
dpi_working.exe input.pcap output.pcap --export-json r.json --export-csv r.csv --top 10

REM Quiet mode — only write the output PCAP, no console output
dpi_working.exe input.pcap output.pcap --quiet --export-csv r.csv
```

#### Rules file format (`rules.txt`)

```ini
[BLOCKED_IPS]
192.168.1.99
10.0.0.5

[BLOCKED_APPS]
TikTok
YouTube

[BLOCKED_DOMAINS]
ads.
*.doubleclick.net

[BLOCKED_PORTS]
6881
3389
```

---

### Real-time Live Capture (`dpi_live.exe`)

> ⚠️ **Must be run as Administrator** — raw sockets require elevated privileges.

Uses Windows Raw Sockets (`WSASocket` + `SIO_RCVALL`) to capture all traffic from a network interface with **no external libraries** like WinPcap or Npcap.

#### Live Dashboard

The terminal auto-refreshes every 500ms:

```
╔═══════════════════════════════════════════════════════════════╗
║   DPI ENGINE v4.0  ─  Live Capture Dashboard   15:30:45      ║
╚═══════════════════════════════════════════════════════════════╝

  Interface: 192.168.1.100   Packets: 8,214   Bytes: 12 MB   Flows: 63
  5,940 pkt/s   8.2 MB/s   Blocked: 0

  ┌── APPLICATION TRAFFIC ──────────┐   ┌── THREAT ALERTS ──────────────┐
  │ YouTube      ############   60% │   │ [15:29:01] CRIT PORT SCAN      │
  │ Google       ###..........   15% │   │ [15:30:12] WARN HIGH BW        │
  │ Discord      ##...........   10% │   │ [15:30:44] INFO Blocked TikTok │
  └─────────────────────────────────┘   └────────────────────────────────┘

  ┌── TOP FLOWS (by bytes) ─────────────────────────────────────────────┐
  │ Source IP          │ App/SNI       │ Destination  │ Bytes  │ Status │
  │ 192.168.1.5        │ www.youtube~  │ 142.250:443  │ 8.1MB  │   ✓   │
  │ 192.168.1.5        │ www.tiktok~   │ 99.86:443    │ 320KB  │  🚫   │
  └─────────────────────────────────────────────────────────────────────┘
  Commands: [Q]uit  [B <ip>]lock IP  [A <app>]  [D <domain>]  [S]ave  [R]eset
```

#### Threat Detection

| Threat | Trigger | Alert Level |
|--------|---------|-------------|
| Port Scan | Same source IP contacts 20+ different ports | 🔴 CRITICAL |
| Connection Flood | 100+ new connections per second from one IP | 🔴 CRITICAL |
| DNS Tunneling | DNS query name longer than 50 characters | 🟡 WARN |
| High Bandwidth | Any flow exceeds 10 MB/s | 🟡 WARN |

#### Interactive Commands

While running, press:
| Key | Action |
|-----|--------|
| `Q` | Quit and auto-save final report |
| `B` | Prompt to block an IP address |
| `A` | Prompt to block an application |
| `D` | Prompt to block a domain |
| `S` | Save JSON + CSV report immediately |
| `R` | Reset all stats and flow table |

#### Usage

```cmd
REM Auto-detect interface
dpi_live.exe

REM Choose interface
dpi_live.exe --iface 192.168.1.100

REM Save captured packets to PCAP
dpi_live.exe --iface 192.168.1.100 --save live.pcap

REM Block apps while capturing
dpi_live.exe --block-app YouTube --block-domain tiktok

REM Monitor only, don't write PCAP
dpi_live.exe --no-save

REM Show all interfaces + help
dpi_live.exe --help
```

On quit, auto-saves:
- `dpi_live_report.csv` — one row per flow
- `dpi_live_report.json` — full summary + flow array

---

## Detected Applications

The engine identifies traffic for **22+ applications** from SNI hostnames:

| App | Detected Domains |
|-----|-----------------|
| Google | `google.com`, `gstatic.com`, `gmail.com` |
| YouTube | `youtube.com`, `ytimg.com`, `googlevideo.com` |
| Facebook | `facebook.com`, `fbcdn.net`, `meta.com` |
| Instagram | `instagram.com`, `cdninstagram.com` |
| TikTok | `tiktok.com`, `bytedance.com`, `tiktokcdn.com` |
| Netflix | `netflix.com`, `nflxvideo.net` |
| Amazon | `amazon.com`, `amazonaws.com`, `cloudfront.net` |
| Microsoft | `microsoft.com`, `azure.com`, `live.com`, `bing.com` |
| Apple | `apple.com`, `icloud.com`, `itunes.com` |
| Discord | `discord.com`, `discordapp.com` |
| GitHub | `github.com`, `githubusercontent.com` |
| Twitter/X | `twitter.com`, `x.com`, `twimg.com` |
| Spotify | `spotify.com`, `scdn.co` |
| Telegram | `telegram.org`, `t.me` |
| WhatsApp | `whatsapp.com`, `whatsapp.net` |
| Zoom | `zoom.us` |
| Cloudflare | `cloudflare.com`, `1.1.1.1` |

**Port-based protocol labels (26 ports):**

`FTP(21)` `SSH(22)` `SMTP(25)` `DNS(53)` `HTTP(80)` `HTTPS(443)` `RDP(3389)` `MySQL(3306)` `PostgreSQL(5432)` `Redis(6379)` `MongoDB(27017)` `WireGuard(51820)` and more.

---

## TLS JA3 Fingerprinting

Every TLS `Client Hello` gets a JA3 fingerprint computed from:
1. TLS version
2. Cipher suite list (GREASE filtered)
3. Extension type list (GREASE filtered)

Result: a 32-character hex string that identifies the TLS library:
```
88ce4ba02de450dca52a1b7cb6b29c7c  → Chrome on Windows
```
Visible in both the terminal report and JSON/CSV exports.

---

## DNS Query Correlation

When a DNS query for `api.tiktok.com` is seen from `192.168.1.5`, this mapping is stored. If a later HTTPS connection from the same IP to port 443 has no SNI (resumed TLS session, 0-RTT), the DNS history fills in the domain name automatically.

---

## Output Formats

### JSON Report (`--export-json`)

```json
{
  "generated": "2026-03-01T15:18:15",
  "summary": {
    "total_packets": 77,
    "forwarded": 76,
    "dropped": 1,
    "active_flows": 43
  },
  "app_distribution": {
    "YouTube": 3,
    "TikTok": 3,
    "Google": 3
  },
  "flows": [
    {
      "src_ip": "192.168.1.100",
      "dst_ip": "99.86.0.100",
      "dst_port": 443,
      "app": "TikTok",
      "sni": "www.tiktok.com",
      "ja3": "88ce4ba02de450dca52a1b7cb6b29c7c",
      "packets": 3,
      "bytes": 246,
      "blocked": true
    }
  ]
}
```

### CSV Report (`--export-csv`)

```csv
src_ip,dst_ip,src_port,dst_port,protocol,app,proto_label,sni,ja3,packets,bytes,blocked
192.168.1.100,99.86.0.100,63971,443,6,TikTok,HTTPS,www.tiktok.com,88ce4b...,3,246,true
192.168.1.100,142.250.185.110,58867,443,6,YouTube,HTTPS,www.youtube.com,88ce4b...,3,247,false
```

---

## Project Structure

```
Packet_analyzer-main/
│
├── include/                # Header files
│   ├── types.h             # FiveTuple, AppType, Connection, DPIStats
│   ├── pcap_reader.h       # PCAP file reader
│   ├── packet_parser.h     # Ethernet/IP/TCP/UDP parser
│   ├── sni_extractor.h     # TLS, HTTP, DNS, QUIC extractors
│   ├── connection_tracker.h# Flow state machine with LRU eviction
│   ├── rule_manager.h      # Blocking rules (IP/app/domain/port)
│   ├── fast_path.h         # Multi-threaded packet processor
│   ├── load_balancer.h     # Consistent-hash load balancer
│   └── platform.h          # Portable byte-order helpers
│
├── src/                    # Source files
│   ├── main_working.cpp    # ← dpi_working.exe (all v4 offline features)
│   ├── dpi_live.cpp        # ← dpi_live.exe    (real-time live capture)
│   ├── dpi_mt.cpp          # ← dpi_engine.exe  (multi-threaded)
│   ├── types.cpp           # App classification logic
│   ├── pcap_reader.cpp
│   ├── packet_parser.cpp
│   ├── sni_extractor.cpp
│   ├── connection_tracker.cpp
│   ├── rule_manager.cpp
│   └── fast_path.cpp
│
├── test_dpi.pcap           # Sample PCAP for testing
├── ARCHITECTURE.md         # Full technical deep-dive
├── build.bat               # Windows one-click build
└── CMakeLists.txt          # CMake build configuration
```

---

## Multi-threaded Architecture (`dpi_engine.exe`)

```
Reader Thread
    │  (hash 5-tuple)
    ▼
Load Balancer Threads     ← consistent hashing keeps flows on same FP
    │
    ▼
Fast Path Threads         ← each has own flow table, rule checker
    │
    ▼
Output Writer Thread      ← serializes PCAP writes
```

Use `--lbs N --fps N` to tune thread counts for your hardware.

---

## Documentation

See **[ARCHITECTURE.md](ARCHITECTURE.md)** for the full technical deep-dive:
- Packet lifecycle (step-by-step from bytes to decision)
- Every data structure explained
- TLS Client Hello parsing diagrams
- Multi-threaded pipeline design
- Performance tuning guide

---

## Build Requirements

| Requirement | Details |
|---|---|
| OS | Windows 10/11 (for `dpi_live.exe`), any OS for offline tools |
| Compiler | GCC 10+ or Clang 12+ with C++17 |
| Dependencies | **None** — pure standard library |
| MSYS2 | https://www.msys2.org/ |
| MinGW | `pacman -S mingw-w64-x86_64-gcc` |

---

## License

MIT License — free to use, modify, and distribute.
