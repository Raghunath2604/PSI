// ============================================================
//  DPI Engine - LIVE CAPTURE v4.0
//  Real-time packet capture from Windows network interface
//  using Windows Raw Sockets (no external dependencies!)
//
//  Features:
//    - Live packet capture (WSASocket + SIO_RCVALL)
//    - Real-time color dashboard (auto-refresh every second)
//    - Threat detection: port scan, connection flood, DNS tunnel
//    - Anomaly alerting with severity levels (INFO/WARN/CRITICAL)
//    - Bandwidth per-flow tracking (bytes/sec)
//    - Interactive commands: q=quit, s=stats, b=block IP, r=reset
//    - Auto-save PCAP of captured traffic
//    - JSON/CSV report on exit
//
//  Run as: Administrator (required for raw sockets)
//  Usage : dpi_live.exe [interface_ip] [options]
// ============================================================

// Must come before any other includes on Windows
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#define _WIN32_WINNT 0x0601

#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <windows.h>
#include <conio.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")

#include <iostream>
#include <fstream>
#include <sstream>
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <deque>
#include <algorithm>
#include <iomanip>
#include <atomic>
#include <thread>
#include <mutex>
#include <chrono>
#include <cstring>
#include <ctime>
#include <string>
#include <functional>
#include <optional>

// -------------------------------
//  ANSI Color Terminal
// -------------------------------
namespace C {
    const char* RST  = "\033[0m";
    const char* BLD  = "\033[1m";
    const char* DIM  = "\033[2m";
    const char* RED  = "\033[31m";
    const char* GRN  = "\033[32m";
    const char* YEL  = "\033[33m";
    const char* BLU  = "\033[34m";
    const char* MAG  = "\033[35m";
    const char* CYN  = "\033[36m";
    const char* WHT  = "\033[37m";
    const char* BRED = "\033[91m";
    const char* BGRN = "\033[92m";
    const char* BYEL = "\033[93m";
    const char* BBLU = "\033[94m";
    const char* BMAG = "\033[95m";
    const char* BCYN = "\033[96m";
    const char* BWHT = "\033[97m";
    const char* CLR  = "\033[2J\033[H";  // clear screen + go home
    const char* EL   = "\033[K";          // erase to end of line
}

// Enable ANSI on Windows
void enableAnsiTerminal() {
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD mode = 0;
    GetConsoleMode(hOut, &mode);
    SetConsoleMode(hOut, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
}

// -------------------------------
//  IP/TCP/UDP raw headers
// -------------------------------
#pragma pack(push, 1)
struct IPHeader {
    uint8_t  ver_ihl;
    uint8_t  tos;
    uint16_t total_len;
    uint16_t id;
    uint16_t frag_offset;
    uint8_t  ttl;
    uint8_t  protocol;
    uint16_t checksum;
    uint32_t src_ip;
    uint32_t dst_ip;
};
struct TCPHeader {
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq;
    uint32_t ack;
    uint8_t  offset_flags;
    uint8_t  flags;
    uint16_t window;
    uint16_t checksum;
    uint16_t urgent;
};
struct UDPHeader {
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t length;
    uint16_t checksum;
};
#pragma pack(pop)

static inline uint16_t bswap16(uint16_t v) { return (v >> 8) | (v << 8); }
static inline uint32_t bswap32(uint32_t v) {
    return ((v & 0xFF000000) >> 24) | ((v & 0x00FF0000) >> 8) |
           ((v & 0x0000FF00) << 8)  | ((v & 0x000000FF) << 24);
}

// -------------------------------
//  Helpers
// -------------------------------
static std::string ip4Str(uint32_t ip_be) {
    // ip is in network byte order (direct from packet)
    uint8_t* b = reinterpret_cast<uint8_t*>(&ip_be);
    char buf[20];
    snprintf(buf, 20, "%u.%u.%u.%u", b[0], b[1], b[2], b[3]);
    return buf;
}

static std::string nowStr() {
    auto now = std::chrono::system_clock::now();
    std::time_t t = std::chrono::system_clock::to_time_t(now);
    struct tm tm_info;
    localtime_s(&tm_info, &t);
    char buf[32];
    strftime(buf, sizeof(buf), "%H:%M:%S", &tm_info);
    return buf;
}

static std::string humanBytes(uint64_t b) {
    if (b < 1024)       return std::to_string(b) + " B";
    if (b < 1048576)    return std::to_string(b/1024) + " KB";
    if (b < 1073741824) return std::to_string(b/1048576) + " MB";
    return std::to_string(b/1073741824) + " GB";
}

// -------------------------------
//  Alert System
// -------------------------------
enum class AlertLevel { INFO, WARN, CRITICAL };
struct Alert {
    AlertLevel   level;
    std::string  msg;
    std::string  time;
};

struct AlertQueue {
    std::deque<Alert> alerts;
    std::mutex        mtx;
    static const int  MAX = 12;

    void push(AlertLevel lvl, const std::string& msg) {
        std::lock_guard<std::mutex> lk(mtx);
        alerts.push_front({lvl, msg, nowStr()});
        if ((int)alerts.size() > MAX) alerts.pop_back();
    }

    std::vector<Alert> get() {
        std::lock_guard<std::mutex> lk(mtx);
        return std::vector<Alert>(alerts.begin(), alerts.end());
    }
};

// -------------------------------
//  SNI Extractor (inline, no deps)
// -------------------------------
static std::optional<std::string> extractSNI(const uint8_t* p, size_t len) {
    if (len < 9) return std::nullopt;
    if (p[0] != 0x16) return std::nullopt;
    if (p[5] != 0x01) return std::nullopt;
    size_t off = 9 + 2 + 32; // skip record hdr, hs hdr, ver, random
    if (off >= len) return std::nullopt;
    uint8_t sid = p[off++]; off += sid;
    if (off + 2 > len) return std::nullopt;
    uint16_t cs = (uint16_t(p[off]) << 8) | p[off+1]; off += 2 + cs;
    if (off >= len) return std::nullopt;
    uint8_t comp = p[off++]; off += comp;
    if (off + 2 > len) return std::nullopt;
    uint16_t ext_total = (uint16_t(p[off]) << 8) | p[off+1]; off += 2;
    size_t ext_end = std::min(off + ext_total, len);
    while (off + 4 <= ext_end) {
        uint16_t etype = (uint16_t(p[off]) << 8) | p[off+1];
        uint16_t elen  = (uint16_t(p[off+2]) << 8) | p[off+3];
        off += 4;
        if (etype == 0 && elen >= 5) {
            // SNI extension
            uint16_t sni_len = (uint16_t(p[off+3]) << 8) | p[off+4];
            if (off + 5 + sni_len <= len)
                return std::string(reinterpret_cast<const char*>(p + off + 5), sni_len);
        }
        off += elen;
    }
    return std::nullopt;
}

static std::optional<std::string> extractHTTPHost(const uint8_t* p, size_t len) {
    if (len < 4) return std::nullopt;
    const char* methods[] = {"GET ", "POST", "PUT ", "HEAD"};
    bool is_http = false;
    for (auto m : methods) if (memcmp(p, m, 4) == 0) { is_http = true; break; }
    if (!is_http) return std::nullopt;
    for (size_t i = 0; i + 6 < len; i++) {
        if ((p[i]=='H'||p[i]=='h') && (p[i+1]=='o'||p[i+1]=='O') &&
            (p[i+2]=='s'||p[i+2]=='S') && (p[i+3]=='t'||p[i+3]=='T') && p[i+4]==':') {
            size_t s = i+5;
            while (s < len && (p[s]==' '||p[s]=='\t')) s++;
            size_t e = s;
            while (e < len && p[e] != '\r' && p[e] != '\n') e++;
            if (e > s) {
                std::string h(reinterpret_cast<const char*>(p+s), e-s);
                auto col = h.find(':');
                if (col != std::string::npos) h = h.substr(0, col);
                return h;
            }
        }
    }
    return std::nullopt;
}

// DNS query extractor
static std::optional<std::string> extractDNS(const uint8_t* p, size_t len) {
    if (len < 12) return std::nullopt;
    if (p[2] & 0x80) return std::nullopt; // Response, not query
    size_t off = 12; std::string dom;
    while (off < len) {
        uint8_t l = p[off++];
        if (l == 0) break;
        if (l > 63) break;
        if (off + l > len) break;
        if (!dom.empty()) dom += '.';
        dom += std::string(reinterpret_cast<const char*>(p+off), l);
        off += l;
    }
    return dom.empty() ? std::nullopt : std::optional<std::string>(dom);
}

// App type from SNI (abbreviated)
static std::string appFromSNI(const std::string& sni) {
    if (sni.empty()) return "UNKNOWN";
    auto c = [&](const char* s){ return sni.find(s) != std::string::npos; };
    if (c("youtube") || c("ytimg"))  return "YouTube";
    if (c("tiktok") || c("bytedance")) return "TikTok";
    if (c("facebook") || c("fbcdn"))   return "Facebook";
    if (c("instagram") || c("cdninstagram")) return "Instagram";
    if (c("google") || c("gstatic") || c("gmail")) return "Google";
    if (c("netflix") || c("nflx"))   return "Netflix";
    if (c("amazon") || c("amazonaws") || c("cloudfront")) return "Amazon";
    if (c("microsoft") || c("azure") || c("live.com") || c("bing")) return "Microsoft";
    if (c("apple") || c("icloud") || c("itunes")) return "Apple";
    if (c("discord") || c("discordapp")) return "Discord";
    if (c("github"))  return "GitHub";
    if (c("twitter") || c("twimg") || c("x.com")) return "Twitter/X";
    if (c("spotify") || c("scdn"))   return "Spotify";
    if (c("telegram") || c(".t.me")) return "Telegram";
    if (c("whatsapp")) return "WhatsApp";
    if (c("zoom.us")) return "Zoom";
    if (c("cloudflare")) return "Cloudflare";
    return "HTTPS";
}

static std::string portToLabel(uint16_t p) {
    switch(p) {
        case 21: return "FTP";    case 22: return "SSH";
        case 23: return "Telnet"; case 25: return "SMTP";
        case 53: return "DNS";    case 80: return "HTTP";
        case 110:return "POP3";   case 143:return "IMAP";
        case 443:return "HTTPS";  case 465:return "SMTPS";
        case 587:return "SMTP";   case 993:return "IMAPS";
        case 995:return "POP3S";  case 1194:return"OpenVPN";
        case 3306:return"MySQL";  case 3389:return"RDP";
        case 5060:return"SIP";    case 5432:return"PgSQL";
        case 6379:return"Redis";  case 8080:return"HTTP-P";
        case 8443:return"HTTPS2"; case 27017:return"Mongo";
        case 51820:return"WGuard";
        default: return "";
    }
}

// App color
static const char* appColor(const std::string& app) {
    if (app == "YouTube")  return C::BRED;
    if (app == "TikTok")   return C::BMAG;
    if (app == "Facebook" || app == "Instagram") return C::BBLU;
    if (app == "Google")   return C::BYEL;
    if (app == "GitHub")   return C::BWHT;
    if (app == "Discord")  return C::BMAG;
    if (app == "Netflix")  return C::BRED;
    if (app == "Spotify")  return C::BGRN;
    if (app == "Zoom")     return C::BCYN;
    if (app == "DNS")      return C::CYN;
    if (app == "HTTPS")    return C::BLU;
    if (app == "HTTP")     return C::YEL;
    return C::WHT;
}

// Alert level color
static const char* alertColor(AlertLevel l) {
    switch(l) {
        case AlertLevel::CRITICAL: return C::BRED;
        case AlertLevel::WARN:     return C::BYEL;
        default:                   return C::BGRN;
    }
}

// -----------------------------------------------
//  Flow tracking
// -----------------------------------------------
struct FlowKey {
    uint32_t src_ip, dst_ip;
    uint16_t src_port, dst_port;
    uint8_t  proto;
    bool operator==(const FlowKey& o) const {
        return src_ip==o.src_ip && dst_ip==o.dst_ip &&
               src_port==o.src_port && dst_port==o.dst_port && proto==o.proto;
    }
};
struct FlowKeyHash {
    size_t operator()(const FlowKey& k) const {
        size_t h = k.src_ip;
        h ^= k.dst_ip + 0x9E3779B9 + (h<<6) + (h>>2);
        h ^= (uint32_t(k.src_port)<<16|k.dst_port) + 0x9E3779B9 + (h<<6) + (h>>2);
        h ^= k.proto + 0x9E3779B9 + (h<<6) + (h>>2);
        return h;
    }
};

using Clock = std::chrono::steady_clock;
using TP    = Clock::time_point;

struct Flow {
    FlowKey  key;
    std::string app;
    std::string sni;
    std::string proto_label;
    uint64_t packets = 0;
    uint64_t bytes   = 0;
    uint64_t bytes_prev = 0;  // for bps calc
    double   bps     = 0;     // bytes/sec
    bool     blocked = false;
    bool     threat  = false;
    TP       first_seen;
    TP       last_seen;
    TP       last_bps_time;
};

// -----------------------------------------------
//  Threat Detector
// -----------------------------------------------
struct ThreatDetector {
    // Port scan: same src, many different dst ports
    std::unordered_map<uint32_t, std::unordered_set<uint16_t>> src_ports_seen;
    // Connection flood: same src, many new connections per second
    std::unordered_map<uint32_t, uint32_t> conn_count;
    // DNS tunnel: very long DNS queries
    static const size_t DNS_TUNNEL_THRESH = 50;
    // Port scan threshold
    static const size_t PORT_SCAN_THRESH  = 20;
    // Flood threshold (connections per interval)
    static const size_t FLOOD_THRESH      = 100;
    std::mutex mtx;

    struct ThreatEvent {
        enum Type { PORT_SCAN, CONN_FLOOD, DNS_TUNNEL, HIGH_BW } type;
        std::string src_ip;
        std::string detail;
    };

    std::vector<ThreatEvent> events;

    void onNewFlow(uint32_t src_ip, uint16_t dst_port) {
        std::lock_guard<std::mutex> lk(mtx);
        auto& ports = src_ports_seen[src_ip];
        ports.insert(dst_port);
        if (ports.size() >= PORT_SCAN_THRESH) {
            events.push_back({ThreatEvent::PORT_SCAN, ip4Str(src_ip),
                std::to_string(ports.size()) + " ports scanned"});
            ports.clear(); // reset to avoid repeated spam
        }
        conn_count[src_ip]++;
        if (conn_count[src_ip] >= FLOOD_THRESH) {
            events.push_back({ThreatEvent::CONN_FLOOD, ip4Str(src_ip),
                std::to_string(conn_count[src_ip]) + " new connections"});
            conn_count[src_ip] = 0;
        }
    }

    void onDNS(uint32_t src_ip, const std::string& dom) {
        std::lock_guard<std::mutex> lk(mtx);
        if (dom.size() > DNS_TUNNEL_THRESH) {
            events.push_back({ThreatEvent::DNS_TUNNEL, ip4Str(src_ip),
                "Long DNS query: " + dom.substr(0, 40) + "..."});
        }
    }

    void onHighBW(uint32_t src_ip, double bps) {
        if (bps > 10e6) { // > 10 MB/s
            std::lock_guard<std::mutex> lk(mtx);
            events.push_back({ThreatEvent::HIGH_BW, ip4Str(src_ip),
                humanBytes(uint64_t(bps)) + "/s"});
        }
    }

    std::vector<ThreatEvent> popEvents() {
        std::lock_guard<std::mutex> lk(mtx);
        auto ev = events;
        events.clear();
        return ev;
    }

    void resetInterval() {
        std::lock_guard<std::mutex> lk(mtx);
        conn_count.clear();
    }
};

// -----------------------------------------------
//  Blocking Rules
// -----------------------------------------------
struct BlockRules {
    std::unordered_set<uint32_t>  ips;
    std::vector<std::string>      apps;
    std::vector<std::string>      domains;
    std::unordered_set<uint16_t>  ports;
    std::mutex                    mtx;

    void addIP(uint32_t ip) {
        std::lock_guard<std::mutex> lk(mtx);
        ips.insert(ip);
    }
    void addApp(const std::string& a) {
        std::lock_guard<std::mutex> lk(mtx);
        apps.push_back(a);
    }
    void addDomain(const std::string& d) {
        std::lock_guard<std::mutex> lk(mtx);
        domains.push_back(d);
    }
    void addPort(uint16_t p) {
        std::lock_guard<std::mutex> lk(mtx);
        ports.insert(p);
    }

    bool check(uint32_t src_ip, uint16_t dst_port,
               const std::string& app, const std::string& sni) const {
        // No lock needed for reads if we accept occasional race during updates
        if (ips.count(src_ip)) return true;
        if (ports.count(dst_port)) return true;
        for (const auto& a : apps)
            if (app.find(a) != std::string::npos) return true;
        for (const auto& d : domains)
            if (!sni.empty() && sni.find(d) != std::string::npos) return true;
        return false;
    }
};

// -----------------------------------------------
//  PCAP writer (for saving captured packets)
// -----------------------------------------------
struct PCAPWriter {
    std::ofstream f;
    std::mutex    mtx;

    bool open(const std::string& fname) {
        f.open(fname, std::ios::binary);
        if (!f.is_open()) return false;
        // Global header
        uint32_t magic   = 0xa1b2c3d4;
        uint16_t vmaj    = 2, vmin = 4;
        int32_t  tzone   = 0;
        uint32_t sigfigs = 0, snaplen = 65535, network = 101; // LINKTYPE_RAW
        f.write(reinterpret_cast<const char*>(&magic),   4);
        f.write(reinterpret_cast<const char*>(&vmaj),    2);
        f.write(reinterpret_cast<const char*>(&vmin),    2);
        f.write(reinterpret_cast<const char*>(&tzone),   4);
        f.write(reinterpret_cast<const char*>(&sigfigs), 4);
        f.write(reinterpret_cast<const char*>(&snaplen), 4);
        f.write(reinterpret_cast<const char*>(&network), 4);
        return true;
    }

    void write(const uint8_t* data, size_t len) {
        std::lock_guard<std::mutex> lk(mtx);
        if (!f.is_open()) return;
        auto now = std::chrono::system_clock::now();
        auto epoch = now.time_since_epoch();
        uint32_t ts_sec  = (uint32_t)std::chrono::duration_cast<std::chrono::seconds>(epoch).count();
        uint32_t ts_usec = (uint32_t)(std::chrono::duration_cast<std::chrono::microseconds>(epoch).count() % 1000000);
        uint32_t il = (uint32_t)len, ol = il;
        f.write(reinterpret_cast<const char*>(&ts_sec),  4);
        f.write(reinterpret_cast<const char*>(&ts_usec), 4);
        f.write(reinterpret_cast<const char*>(&il),      4);
        f.write(reinterpret_cast<const char*>(&ol),      4);
        f.write(reinterpret_cast<const char*>(data), len);
    }
};

// -----------------------------------------------
//  Global State
// -----------------------------------------------
struct DPIState {
    std::unordered_map<FlowKey, Flow, FlowKeyHash> flows;
    std::mutex flows_mtx;

    std::unordered_map<std::string, uint64_t> app_packets;
    std::unordered_map<std::string, uint64_t> app_bytes;

    std::atomic<uint64_t> total_packets{0};
    std::atomic<uint64_t> total_bytes  {0};
    std::atomic<uint64_t> dropped{0};
    std::atomic<uint64_t> pps{0};   // packets per sec
    std::atomic<uint64_t> bps{0};   // bytes per sec

    uint64_t prev_packets = 0;
    uint64_t prev_bytes   = 0;

    AlertQueue   alerts;
    ThreatDetector threats;
    BlockRules   rules;
    PCAPWriter   pcap;

    std::atomic<bool> running{true};
    std::string iface_ip;
    std::string out_pcap;

    // DNS correlation: IP -> recent domain
    std::unordered_map<uint32_t, std::string> dns_map;
    std::mutex dns_mtx;
};

DPIState G;

// -----------------------------------------------
//  List network interfaces
// -----------------------------------------------
std::vector<std::pair<std::string, std::string>> listInterfaces() {
    std::vector<std::pair<std::string, std::string>> ifaces;
    ULONG bufLen = 15000;
    std::vector<BYTE> buf(bufLen);
    auto pInfo = reinterpret_cast<PIP_ADAPTER_INFO>(buf.data());
    if (GetAdaptersInfo(pInfo, &bufLen) != ERROR_SUCCESS) {
        buf.resize(bufLen);
        pInfo = reinterpret_cast<PIP_ADAPTER_INFO>(buf.data());
        if (GetAdaptersInfo(pInfo, &bufLen) != ERROR_SUCCESS) return ifaces;
    }
    for (auto p = pInfo; p; p = p->Next) {
        std::string name = p->Description;
        std::string ip   = p->IpAddressList.IpAddress.String;
        if (ip != "0.0.0.0")
            ifaces.push_back({name, ip});
    }
    return ifaces;
}

// -----------------------------------------------
//  Packet processing
// -----------------------------------------------
void processPacket(const uint8_t* data, size_t len, bool save) {
    if (len < sizeof(IPHeader)) return;
    const IPHeader* ip = reinterpret_cast<const IPHeader*>(data);
    uint8_t ihl = (ip->ver_ihl & 0x0F) * 4;
    if (ihl < 20 || ihl > len) return;

    FlowKey key;
    key.src_ip  = ip->src_ip;
    key.dst_ip  = ip->dst_ip;
    key.proto   = ip->protocol;
    key.src_port = 0; key.dst_port = 0;

    const uint8_t* transport = data + ihl;
    size_t         trans_len = len - ihl;
    const uint8_t* payload   = nullptr;
    size_t         pay_len   = 0;

    if (ip->protocol == 6 && trans_len >= sizeof(TCPHeader)) {
        const TCPHeader* tcp = reinterpret_cast<const TCPHeader*>(transport);
        key.src_port = bswap16(tcp->src_port);
        key.dst_port = bswap16(tcp->dst_port);
        size_t tcp_hdr = ((tcp->offset_flags >> 4) & 0xF) * 4;
        if (tcp_hdr <= trans_len) { payload = transport + tcp_hdr; pay_len = trans_len - tcp_hdr; }
    } else if (ip->protocol == 17 && trans_len >= sizeof(UDPHeader)) {
        const UDPHeader* udp = reinterpret_cast<const UDPHeader*>(transport);
        key.src_port = bswap16(udp->src_port);
        key.dst_port = bswap16(udp->dst_port);
        payload = transport + 8; pay_len = trans_len > 8 ? trans_len - 8 : 0;
    } else {
        return; // Only TCP/UDP
    }

    bool is_new = false;
    {
        std::lock_guard<std::mutex> lk(G.flows_mtx);
        auto it = G.flows.find(key);
        is_new = (it == G.flows.end());
        if (is_new) {
            Flow& fl = G.flows[key];
            fl.key        = key;
            fl.first_seen = Clock::now();
            fl.last_bps_time = fl.first_seen;
            fl.proto_label = portToLabel(key.dst_port);
            if (fl.proto_label.empty()) fl.proto_label = portToLabel(key.src_port);
            fl.app = "UNKNOWN";
        }
        Flow& fl = G.flows[key];
        fl.packets++;
        fl.bytes += len;
        fl.last_seen = Clock::now();

        // BPS calculation
        auto now = Clock::now();
        double elapsed = std::chrono::duration<double>(now - fl.last_bps_time).count();
        if (elapsed >= 1.0) {
            fl.bps = double(fl.bytes - fl.bytes_prev) / elapsed;
            fl.bytes_prev   = fl.bytes;
            fl.last_bps_time = now;
            G.threats.onHighBW(key.src_ip, fl.bps);
        }

        // DNS (port 53 UDP)
        if (key.dst_port == 53 && payload && pay_len > 12) {
            auto dom = extractDNS(payload, pay_len);
            if (dom) {
                fl.app = "DNS";
                fl.sni = *dom;
                std::lock_guard<std::mutex> dlk(G.dns_mtx);
                G.dns_map[key.src_ip] = *dom;
                G.threats.onDNS(key.src_ip, *dom);
            }
        }

        // TLS SNI (port 443)
        if (key.dst_port == 443 && fl.sni.empty() && payload && pay_len > 5) {
            auto sni = extractSNI(payload, pay_len);
            if (sni) {
                fl.sni = *sni;
                fl.app = appFromSNI(*sni);
                G.app_packets[fl.app]++;
                G.app_bytes[fl.app] += len;
            }
        }

        // HTTP Host (port 80)
        if (key.dst_port == 80 && fl.sni.empty() && payload && pay_len > 4) {
            auto h = extractHTTPHost(payload, pay_len);
            if (h) {
                fl.sni = *h;
                fl.app = appFromSNI(*h);
                if (fl.app == "HTTPS") fl.app = "HTTP";
            }
        }

        // DNS correlation fallback
        if (fl.sni.empty() && key.dst_port == 443) {
            std::lock_guard<std::mutex> dlk(G.dns_mtx);
            auto dit = G.dns_map.find(key.src_ip);
            if (dit != G.dns_map.end())
                fl.sni = dit->second + " (dns)";
        }

        // Port fallback
        if (fl.app == "UNKNOWN" && !fl.proto_label.empty())
            fl.app = fl.proto_label;

        // Blocking
        if (!fl.blocked)
            fl.blocked = G.rules.check(key.src_ip, key.dst_port, fl.app, fl.sni);
    }

    if (is_new) G.threats.onNewFlow(key.src_ip, key.dst_port);

    G.total_packets++;
    G.total_bytes += len;
    if (save && !G.out_pcap.empty()) G.pcap.write(data, len);

    // Check threats and push alerts
    for (auto& ev : G.threats.popEvents()) {
        AlertLevel lvl = AlertLevel::WARN;
        std::string msg;
        switch (ev.type) {
            case ThreatDetector::ThreatEvent::PORT_SCAN:
                lvl = AlertLevel::CRITICAL;
                msg = "PORT SCAN from " + ev.src_ip + " – " + ev.detail;
                break;
            case ThreatDetector::ThreatEvent::CONN_FLOOD:
                lvl = AlertLevel::CRITICAL;
                msg = "CONN FLOOD from " + ev.src_ip + " – " + ev.detail;
                break;
            case ThreatDetector::ThreatEvent::DNS_TUNNEL:
                lvl = AlertLevel::WARN;
                msg = "DNS TUNNEL? " + ev.src_ip + " – " + ev.detail;
                break;
            case ThreatDetector::ThreatEvent::HIGH_BW:
                lvl = AlertLevel::WARN;
                msg = "HIGH BW from " + ev.src_ip + " – " + ev.detail;
                break;
        }
        G.alerts.push(lvl, msg);
    }
}

// -----------------------------------------------
//  Dashboard rendering
// -----------------------------------------------
void renderDashboard() {
    auto now      = std::chrono::system_clock::now();
    std::time_t t = std::chrono::system_clock::to_time_t(now);
    struct tm tm_info; localtime_s(&tm_info, &t);
    char timebuf[32]; strftime(timebuf, sizeof(timebuf), "%Y-%m-%d %H:%M:%S", &tm_info);

    uint64_t total = G.total_packets.load();
    uint64_t bytes = G.total_bytes.load();
    uint64_t drop  = G.dropped.load();
    uint64_t pps   = G.pps.load();
    uint64_t bps   = G.bps.load();

    // Copy flows safely
    std::vector<Flow> flows_snap;
    {
        std::lock_guard<std::mutex> lk(G.flows_mtx);
        flows_snap.reserve(G.flows.size());
        for (const auto& [k, v] : G.flows) flows_snap.push_back(v);
    }

    // Sort by bytes desc
    std::sort(flows_snap.begin(), flows_snap.end(),
              [](const Flow& a, const Flow& b){ return a.bytes > b.bytes; });

    // App stats
    std::unordered_map<std::string, uint64_t> app_pkt;
    for (const auto& fl : flows_snap) app_pkt[fl.app] += fl.packets;
    std::vector<std::pair<std::string, uint64_t>> apps(app_pkt.begin(), app_pkt.end());
    std::sort(apps.begin(), apps.end(),
              [](const auto& a, const auto& b){ return a.second > b.second; });

    // Begin rendering to string buffer
    std::ostringstream o;
    o << C::CLR;

    o << C::BLD << C::BCYN
      << "╔══════════════════════════════════════════════════════════════════════════╗\n"
      << "║   🔍  DPI ENGINE v4.0  ─  Live Capture Dashboard       " << timebuf << "  ║\n"
      << "╚══════════════════════════════════════════════════════════════════════════╝\n"
      << C::RST;

    // Stats row
    o << C::BLD << C::BWHT;
    o << "  Interface: " << C::BCYN << G.iface_ip << C::BWHT
      << "   Packets: " << C::BGRN << total << C::BWHT
      << "   Bytes: " << C::BGRN << humanBytes(bytes) << C::BWHT
      << "   Flows: " << C::BMAG << flows_snap.size() << C::BWHT
      << "   Blocked: " << C::BRED << drop << C::BWHT
      << "   " << C::BYEL << pps << " pkt/s" << C::BWHT
      << "   " << C::BYEL << humanBytes(bps) << "/s" << C::RST << "\n\n";

    // Two-column layout: Apps | Threats
    // App distribution (left)
    o << C::BLD << C::BBLU << "  ┌── APPLICATION TRAFFIC ────────────────────┐"
      << "   ┌── 🚨 THREAT ALERTS ─────────────────────┐\n" << C::RST;

    auto alerts = G.alerts.get();
    int max_app_rows = 10;
    size_t app_rows = std::min((int)apps.size(), max_app_rows);

    for (size_t i = 0; i < (size_t)max_app_rows; i++) {
        // Left: app
        o << C::BLD << C::BBLU << "  │ " << C::RST;
        if (i < app_rows) {
            const auto& [app, cnt] = apps[i];
            double pct = total > 0 ? 100.0 * cnt / total : 0;
            int bar_w = std::min(20, (int)(pct / 5));
            std::string bar_s(bar_w, '#'), bar_e(20 - bar_w, '.');
            o << appColor(app) << C::BLD << std::setw(12) << std::left << app << C::RST
              << " " << C::GRN << bar_s << C::DIM << bar_e << C::RST
              << " " << std::setw(5) << std::right << std::fixed << std::setprecision(1) << pct << "%";
            o << " " << C::BLD << C::BBLU << "│" << C::RST;
        } else {
            o << std::setw(42) << " " << C::BLD << C::BBLU << "│" << C::RST;
        }

        // Right: alerts
        o << "   " << C::BLD << C::BRED << "│ " << C::RST;
        if (i < alerts.size()) {
            const auto& a = alerts[i];
            std::string m = a.msg.size() > 38 ? a.msg.substr(0, 36) + ".." : a.msg;
            o << alertColor(a.level) << "[" << a.time << "] " 
              << (a.level == AlertLevel::CRITICAL ? "CRIT" : a.level == AlertLevel::WARN ? "WARN" : "INFO")
              << C::RST << " " << C::BWHT << m << C::RST;
            // Pad
            int pad = 40 - (int)m.size() - 16;
            o << std::string(std::max(0, pad), ' ');
        } else {
            o << std::setw(42) << " ";
        }
        o << C::BLD << C::BRED << "│" << C::RST << "\n";
    }

    o << C::BLD << C::BBLU << "  └───────────────────────────────────────────┘"
      << "   └─────────────────────────────────────────┘\n\n" << C::RST;

    // Top flows table
    o << C::BLD << C::BYEL
      << "  ┌────────────────────────────────────────────────────────────────────────┐\n"
      << "  │           TOP FLOWS (by bytes)                                        │\n"
      << "  ├─────────────────────┬──────────────┬─────────────┬────────┬────────┬──┤\n"
      << "  │ Source IP           │ App/SNI      │ Dst         │ Pkts   │ Bytes  │St│\n"
      << "  ├─────────────────────┼──────────────┼─────────────┼────────┼────────┼──┤\n"
      << C::RST;

    int max_flow_rows = 12;
    size_t frows = std::min((int)flows_snap.size(), max_flow_rows);
    for (size_t i = 0; i < frows; i++) {
        const Flow& fl = flows_snap[i];
        std::string src  = ip4Str(fl.key.src_ip);
        std::string dst  = ip4Str(fl.key.dst_ip) + ":" + std::to_string(fl.key.dst_port);
        std::string label = fl.sni.empty() ? fl.app : fl.sni;
        if (label.size() > 12) label = label.substr(0, 11) + "~";
        if (src.size()   > 19) src   = src.substr(0, 18) + "~";
        if (dst.size()   > 11) dst   = dst.substr(0, 10) + "~";

        const char* status_color = fl.blocked ? C::BRED : (fl.threat ? C::BYEL : C::BGRN);
        const char* status_sym   = fl.blocked ? "🚫" : (fl.threat ? "⚠" : "✓");

        o << "  │ " << appColor(fl.app) << std::setw(19) << std::left << src << C::RST
          << " │ " << appColor(fl.app) << C::BLD << std::setw(12) << std::left << label << C::RST
          << " │ " << C::DIM << std::setw(11) << std::left << dst << C::RST
          << " │ " << std::setw(6) << fl.packets
          << " │ " << std::setw(6) << humanBytes(fl.bytes)
          << " │" << status_color << status_sym << C::RST << "│\n";
    }

    o << C::BLD << C::BYEL
      << "  └─────────────────────┴──────────────┴─────────────┴────────┴────────┴──┘\n"
      << C::RST;

    // Commands hint
    o << "\n  " << C::DIM << "Commands: " << C::RST
      << C::BWHT << "[Q]" << C::RST << "uit  "
      << C::BWHT << "[B <ip>]" << C::RST << "lock IP  "
      << C::BWHT << "[A <app>]" << C::RST << "pp block  "
      << C::BWHT << "[D <dom>]" << C::RST << "omain block  "
      << C::BWHT << "[S]" << C::RST << "ave report  "
      << C::BWHT << "[R]" << C::RST << "eset stats\n";

    // Write all at once (minimize flicker)
    std::cout << o.str() << std::flush;
}

// -----------------------------------------------
//  Save final report
// -----------------------------------------------
void saveReport(const std::string& prefix) {
    std::lock_guard<std::mutex> lk(G.flows_mtx);
    // CSV
    {
        std::ofstream f(prefix + "_report.csv");
        f << "src_ip,dst_ip,src_port,dst_port,proto,app,sni,packets,bytes,bps,blocked\n";
        for (const auto& [k, fl] : G.flows) {
            f << ip4Str(k.src_ip) << "," << ip4Str(k.dst_ip) << ","
              << k.src_port << "," << k.dst_port << "," << (int)k.proto << ","
              << fl.app << "," << fl.sni << ","
              << fl.packets << "," << fl.bytes << "," << (int)fl.bps << ","
              << (fl.blocked ? "true" : "false") << "\n";
        }
        std::cerr << "[DPI] CSV saved: " << prefix << "_report.csv\n";
    }
    // JSON summary
    {
        std::ofstream f(prefix + "_report.json");
        f << "{\n  \"total_packets\": " << G.total_packets.load()
          << ",\n  \"total_bytes\": " << G.total_bytes.load()
          << ",\n  \"total_flows\": " << G.flows.size()
          << ",\n  \"dropped\": " << G.dropped.load()
          << ",\n  \"flows\": [\n";
        bool first = true;
        for (const auto& [k, fl] : G.flows) {
            if (!first) f << ",\n";
            f << "    {\"src\":\"" << ip4Str(k.src_ip)
              << "\",\"dst\":\"" << ip4Str(k.dst_ip) << "\",\"dport\":" << k.dst_port
              << ",\"app\":\"" << fl.app << "\",\"sni\":\"" << fl.sni
              << "\",\"pkts\":" << fl.packets << ",\"bytes\":" << fl.bytes
              << ",\"blocked\":" << (fl.blocked ? "true": "false") << "}";
            first = false;
        }
        f << "\n  ]\n}\n";
        std::cerr << "[DPI] JSON saved: " << prefix << "_report.json\n";
    }
}

// -----------------------------------------------
//  Interactive command thread
// -----------------------------------------------
void commandThread() {
    while (G.running) {
        if (_kbhit()) {
            char ch = _getch();
            if (ch == 'q' || ch == 'Q') {
                G.running = false;
            } else if (ch == 's' || ch == 'S') {
                saveReport("dpi_live");
                G.alerts.push(AlertLevel::INFO, "Report saved: dpi_live_report.*");
            } else if (ch == 'r' || ch == 'R') {
                std::lock_guard<std::mutex> lk(G.flows_mtx);
                G.flows.clear();
                G.total_packets = 0; G.total_bytes = 0; G.dropped = 0;
                G.alerts.push(AlertLevel::INFO, "Stats reset");
            } else if (ch == 'b' || ch == 'B') {
                // Block IP - read from stdin in simple mode
                // (In a real terminal we'd need ncurses)
                std::string ip;
                std::cout << "\nBlock IP: "; std::cin >> ip;
                // Parse IP to uint32 (network byte order)
                uint32_t addr = 0;
                int octet = 0, shift = 24;
                for (char c : ip) {
                    if (c == '.') { addr |= (octet << shift); shift -= 8; octet = 0; }
                    else if (c >= '0' && c <= '9') octet = octet*10+(c-'0');
                }
                addr |= (octet << shift);
                // Convert to network order for matching
                addr = bswap32(addr);
                G.rules.addIP(addr);
                G.alerts.push(AlertLevel::INFO, "Blocked IP: " + ip);
            } else if (ch == 'a' || ch == 'A') {
                std::string app;
                std::cout << "\nBlock App: "; std::cin >> app;
                G.rules.addApp(app);
                G.alerts.push(AlertLevel::INFO, "Blocked App: " + app);
            } else if (ch == 'd' || ch == 'D') {
                std::string dom;
                std::cout << "\nBlock Domain: "; std::cin >> dom;
                G.rules.addDomain(dom);
                G.alerts.push(AlertLevel::INFO, "Blocked Domain: " + dom);
            }
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
}

// -----------------------------------------------
//  Stats update thread (pps/bps)
// -----------------------------------------------
void statsThread() {
    while (G.running) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
        uint64_t cur_p = G.total_packets.load();
        uint64_t cur_b = G.total_bytes.load();
        G.pps.store(cur_p - G.prev_packets);
        G.bps.store(cur_b - G.prev_bytes);
        G.prev_packets = cur_p;
        G.prev_bytes   = cur_b;
        G.threats.resetInterval();
    }
}

// -----------------------------------------------
//  Dashboard refresh thread
// -----------------------------------------------
void dashThread() {
    while (G.running) {
        renderDashboard();
        std::this_thread::sleep_for(std::chrono::milliseconds(500)); // 2 fps
    }
}

// -----------------------------------------------
//  Usage
// -----------------------------------------------
void printUsage(const char* prog) {
    std::cout << C::BLD << C::BCYN << "\n"
              << "═══════════════════════════════════════════════\n"
              << "  DPI Engine v4.0 - Live Capture Edition\n"
              << "═══════════════════════════════════════════════\n"
              << C::RST << "\n"
              << "Usage: " << prog << " [options]\n\n"
              << "Options:\n"
              << "  --iface <ip>        Network interface IP (default: 0.0.0.0 = first)\n"
              << "  --save <file.pcap>  Save captured packets to PCAP\n"
              << "  --block-app <app>   Block application (YouTube, TikTok...)\n"
              << "  --block-domain <d>  Block domain (substring match)\n"
              << "  --block-port <p>    Block destination port\n"
              << "  --no-save           Don't save to PCAP\n\n"
              << C::BYEL << "⚠  Must run as Administrator for raw socket access!\n\n"
              << C::RST
              << "Available Interfaces:\n";

    auto ifaces = listInterfaces();
    for (size_t i = 0; i < ifaces.size(); i++) {
        std::cout << "  [" << i << "] " << ifaces[i].second
                  << "  (" << ifaces[i].first << ")\n";
    }
    std::cout << "\nExample:\n"
              << "  " << prog << " --iface 192.168.1.100 --save capture.pcap\n"
              << "  " << prog << " --block-app YouTube --block-domain ads.\n\n";
}

// -----------------------------------------------
//  Main
// -----------------------------------------------
int main(int argc, char* argv[]) {
    enableAnsiTerminal();

    // Default options
    std::string iface_ip = "";
    bool do_save = true;
    G.out_pcap = "dpi_live_capture.pcap";

    // Parse args
    for (int i = 1; i < argc; i++) {
        std::string a = argv[i];
        if (a == "--help" || a == "-h") { printUsage(argv[0]); return 0; }
        if (a == "--iface"       && i+1 < argc) iface_ip = argv[++i];
        if (a == "--save"        && i+1 < argc) G.out_pcap = argv[++i];
        if (a == "--no-save")    do_save = false;
        if (a == "--block-app"   && i+1 < argc) G.rules.addApp(argv[++i]);
        if (a == "--block-domain"&& i+1 < argc) G.rules.addDomain(argv[++i]);
        if (a == "--block-port"  && i+1 < argc) {
            try { G.rules.addPort(uint16_t(std::stoi(argv[++i]))); } catch(...) {}
        }
    }

    // If no iface given, auto-detect
    if (iface_ip.empty()) {
        auto ifaces = listInterfaces();
        if (!ifaces.empty()) iface_ip = ifaces[0].second;
        else { std::cerr << "No network interfaces found!\n"; return 1; }
    }
    G.iface_ip = iface_ip;

    std::cout << C::BLD << C::BCYN << "\n  DPI Engine v4.0 – Live Capture Starting…\n"
              << C::RST;
    std::cout << "  Interface: " << iface_ip << "\n";
    if (do_save) {
        std::cout << "  Saving to: " << G.out_pcap << "\n";
        if (!G.pcap.open(G.out_pcap)) do_save = false;
    }

    // Initialize Winsock
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2,2), &wsa) != 0) {
        std::cerr << "WSAStartup failed: " << WSAGetLastError() << "\n";
        return 1;
    }

    // Create raw socket
    SOCKET s = WSASocket(AF_INET, SOCK_RAW, IPPROTO_IP,
                         nullptr, 0, WSA_FLAG_OVERLAPPED);
    if (s == INVALID_SOCKET) {
        int err = WSAGetLastError();
        std::cerr << C::BRED << "\n  ERROR: Cannot create raw socket (code " << err << ")\n"
                  << C::BYEL << "  → Run this program as Administrator!\n" << C::RST;
        WSACleanup();
        return 1;
    }

    // Bind to interface
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port   = 0;
    inet_pton(AF_INET, iface_ip.c_str(), &addr.sin_addr);
    if (bind(s, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == SOCKET_ERROR) {
        std::cerr << "Bind failed: " << WSAGetLastError() << "\n";
        closesocket(s); WSACleanup(); return 1;
    }

    // Enable promiscuous mode (SIO_RCVALL)
    DWORD optval = 1, ret = 0;
    if (WSAIoctl(s, SIO_RCVALL, &optval, sizeof(optval),
                 nullptr, 0, &ret, nullptr, nullptr) == SOCKET_ERROR) {
        std::cerr << "SIO_RCVALL failed: " << WSAGetLastError()
                  << " (Run as Administrator!)\n";
        closesocket(s); WSACleanup(); return 1;
    }

    std::cout << C::BGRN << "  ✓ Capture started!  Press Q to quit, S to save.\n\n"
              << C::RST;
    std::this_thread::sleep_for(std::chrono::milliseconds(800));

    // Start background threads
    std::thread stats_t(statsThread);
    std::thread dash_t(dashThread);
    std::thread cmd_t(commandThread);

    // Main capture loop
    std::vector<uint8_t> buf(65536);
    while (G.running) {
        int recv_len = recv(s, reinterpret_cast<char*>(buf.data()), (int)buf.size(), 0);
        if (recv_len == SOCKET_ERROR) {
            if (!G.running) break;
            int err = WSAGetLastError();
            if (err == WSAEINTR || err == WSAENOTSOCK) break;
            continue;
        }
        if (recv_len > 0) {
            processPacket(buf.data(), recv_len, do_save);
        }
    }

    // Shutdown
    G.running = false;
    DWORD off = 0;
    WSAIoctl(s, SIO_RCVALL, &off, sizeof(off), nullptr, 0, &ret, nullptr, nullptr);
    closesocket(s);
    WSACleanup();

    stats_t.join();
    dash_t.join();
    cmd_t.join();

    // Final report
    std::cout << C::CLR;
    std::cout << C::BGRN << "\n  Capture stopped. Saving final reports...\n" << C::RST;
    saveReport("dpi_live");

    std::cout << "\n  " << C::BLD << "Total packets: " << C::BGRN << G.total_packets.load() << C::RST
              << "  Total bytes: " << C::BGRN << humanBytes(G.total_bytes.load()) << C::RST
              << "  Flows: " << C::BGRN << [&](){ std::lock_guard<std::mutex> l(G.flows_mtx); return G.flows.size(); }() << C::RST
              << "\n\n";
    return 0;
}
