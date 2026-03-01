// ============================================================
// DPI Engine v3.0 - Enhanced with 7 new features
// Features:
//   1. Extended protocol detection (SSH, FTP, SMTP, RDP, etc.)
//   2. TLS JA3-style fingerprinting
//   3. DNS query correlation
//   4. Top-N flow reporter
//   5. JSON export (--export-json)
//   6. CSV export  (--export-csv)
//   7. Config file (--rules <file>)
// ============================================================

#include <iostream>
#include <fstream>
#include <sstream>
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <algorithm>
#include <iomanip>
#include <cstring>
#include <chrono>
#include <ctime>
#include <functional>

#include "pcap_reader.h"
#include "packet_parser.h"
#include "sni_extractor.h"
#include "types.h"

using namespace PacketAnalyzer;
using namespace DPI;

// ============================================================
// Feature 1: Extended Protocol Detection
// ============================================================
struct PortProtocol {
    uint16_t port;
    AppType app;
    const char* label;
};

static const PortProtocol PORT_TABLE[] = {
    {21,   AppType::HTTP,       "FTP"},
    {22,   AppType::TLS,        "SSH"},
    {23,   AppType::HTTP,       "Telnet"},
    {25,   AppType::HTTP,       "SMTP"},
    {53,   AppType::DNS,        "DNS"},
    {80,   AppType::HTTP,       "HTTP"},
    {110,  AppType::HTTP,       "POP3"},
    {143,  AppType::HTTP,       "IMAP"},
    {443,  AppType::HTTPS,      "HTTPS"},
    {465,  AppType::TLS,        "SMTPS"},
    {587,  AppType::TLS,        "SMTP-TLS"},
    {993,  AppType::TLS,        "IMAPS"},
    {995,  AppType::TLS,        "POP3S"},
    {1194, AppType::QUIC,       "OpenVPN"},
    {1433, AppType::HTTP,       "MSSQL"},
    {3306, AppType::HTTP,       "MySQL"},
    {3389, AppType::HTTP,       "RDP"},
    {5060, AppType::HTTP,       "SIP"},
    {5432, AppType::HTTP,       "PostgreSQL"},
    {5222, AppType::HTTP,       "XMPP"},
    {6379, AppType::HTTP,       "Redis"},
    {6881, AppType::HTTP,       "BitTorrent"},
    {8080, AppType::HTTP,       "HTTP-Proxy"},
    {8443, AppType::HTTPS,      "HTTPS-Alt"},
    {9000, AppType::HTTP,       "FastCGI"},
    {27017,AppType::HTTP,       "MongoDB"},
    {51820,AppType::QUIC,       "WireGuard"},
};

std::string portToProtocolLabel(uint16_t port) {
    for (const auto& pp : PORT_TABLE) {
        if (pp.port == port) return pp.label;
    }
    return "";
}

AppType portToAppType(uint16_t port) {
    for (const auto& pp : PORT_TABLE) {
        if (pp.port == port) return pp.app;
    }
    return AppType::UNKNOWN;
}

// ============================================================
// Feature 2: TLS JA3-style Fingerprinting
// ============================================================
struct TLSFingerprint {
    uint16_t tls_version = 0;
    std::vector<uint16_t> cipher_suites;
    std::vector<uint16_t> extensions;
    std::string ja3_string;
    std::string ja3_hex;

    bool empty() const { return cipher_suites.empty(); }
};

// Simple MD5-like hash (djb2 variant) for JA3 - no external deps needed
static std::string hashFingerprint(const std::string& data) {
    uint32_t h1 = 5381, h2 = 0x9E3779B9;
    for (unsigned char c : data) {
        h1 = ((h1 << 5) + h1) ^ c;
        h2 = ((h2 << 5) + h2) ^ c;
    }
    std::ostringstream ss;
    ss << std::hex << std::setfill('0') << std::setw(8) << h1
       << std::setw(8) << h2
       << std::setw(8) << (h1 ^ h2)
       << std::setw(8) << (h1 + h2);
    return ss.str();
}

static inline uint16_t readU16BE(const uint8_t* p) {
    return (uint16_t(p[0]) << 8) | p[1];
}

TLSFingerprint extractJA3(const uint8_t* payload, size_t length) {
    TLSFingerprint fp;
    // Minimal length check for TLS record + handshake header
    if (length < 43) return fp;
    if (payload[0] != 0x16) return fp;       // Content type: handshake
    if (payload[5] != 0x01) return fp;       // Handshake type: client hello

    size_t offset = 9;  // Skip: record hdr(5) + handshake type(1) + len(3)
    if (offset + 2 > length) return fp;
    fp.tls_version = readU16BE(payload + offset);
    offset += 2;  // client version

    offset += 32; // skip random
    if (offset >= length) return fp;

    // Session ID
    uint8_t sid_len = payload[offset++];
    offset += sid_len;
    if (offset + 2 > length) return fp;

    // Cipher suites
    uint16_t cs_len = readU16BE(payload + offset);
    offset += 2;
    size_t cs_end = offset + cs_len;
    if (cs_end > length) return fp;
    while (offset + 2 <= cs_end) {
        uint16_t cs = readU16BE(payload + offset);
        // Skip GREASE values (0xXAXA pattern)
        if ((cs & 0x0F0F) != 0x0A0A)
            fp.cipher_suites.push_back(cs);
        offset += 2;
    }
    offset = cs_end;

    // Compression methods
    if (offset >= length) return fp;
    uint8_t comp_len = payload[offset++];
    offset += comp_len;

    // Extensions
    if (offset + 2 > length) return fp;
    uint16_t ext_total = readU16BE(payload + offset);
    offset += 2;
    size_t ext_end = offset + ext_total;
    if (ext_end > length) ext_end = length;

    while (offset + 4 <= ext_end) {
        uint16_t ext_type = readU16BE(payload + offset);
        uint16_t ext_len  = readU16BE(payload + offset + 2);
        offset += 4;
        if ((ext_type & 0x0F0F) != 0x0A0A)  // skip GREASE
            fp.extensions.push_back(ext_type);
        offset += ext_len;
    }

    // Build JA3 string: version,ciphers,extensions
    std::ostringstream ja3;
    ja3 << fp.tls_version << ",";
    for (size_t i = 0; i < fp.cipher_suites.size(); i++) {
        if (i) ja3 << "-";
        ja3 << fp.cipher_suites[i];
    }
    ja3 << ",";
    for (size_t i = 0; i < fp.extensions.size(); i++) {
        if (i) ja3 << "-";
        ja3 << fp.extensions[i];
    }
    fp.ja3_string = ja3.str();
    fp.ja3_hex    = hashFingerprint(fp.ja3_string);
    return fp;
}

// ============================================================
// Feature 3: DNS Query Correlation
// ============================================================
struct DNSCorrelator {
    // Map: IP address (uint32) -> set of domains it resolved recently
    std::unordered_map<uint32_t, std::vector<std::string>> ip_to_domains;

    void recordDNSQuery(const uint8_t* udp_payload, size_t len, uint32_t client_ip) {
        auto domain = DNSExtractor::extractQuery(udp_payload, len);
        if (domain && !domain->empty()) {
            ip_to_domains[client_ip].push_back(*domain);
            if (ip_to_domains[client_ip].size() > 50) // cap per IP
                ip_to_domains[client_ip].erase(ip_to_domains[client_ip].begin());
        }
    }

    // Try to match an HTTPS flow's SNI using recent DNS queries
    std::string correlate(uint32_t client_ip, const std::string& existing_sni) {
        if (!existing_sni.empty()) return existing_sni;
        auto it = ip_to_domains.find(client_ip);
        if (it != ip_to_domains.end() && !it->second.empty())
            return it->second.back(); // Most recent query
        return "";
    }
};

// ============================================================
// Flow definition (extended)
// ============================================================
struct Flow {
    FiveTuple tuple;
    AppType app_type  = AppType::UNKNOWN;
    std::string sni;
    std::string proto_label;   // FTP, SSH, RDP, etc.
    TLSFingerprint ja3;
    uint64_t packets = 0;
    uint64_t bytes   = 0;
    bool blocked     = false;
    std::chrono::steady_clock::time_point first_seen;
    std::chrono::steady_clock::time_point last_seen;
};

// ============================================================
// Blocking Rules
// ============================================================
class BlockingRules {
public:
    std::unordered_set<uint32_t>  blocked_ips;
    std::unordered_set<AppType>   blocked_apps;
    std::vector<std::string>      blocked_domains;
    std::unordered_set<uint16_t>  blocked_ports;

    void blockIP(const std::string& ip) {
        uint32_t addr = parseIP(ip);
        blocked_ips.insert(addr);
        std::cout << "[Rules] Blocked IP: " << ip << "\n";
    }
    void blockApp(const std::string& app) {
        for (int i = 0; i < static_cast<int>(AppType::APP_COUNT); i++) {
            if (appTypeToString(static_cast<AppType>(i)) == app) {
                blocked_apps.insert(static_cast<AppType>(i));
                std::cout << "[Rules] Blocked app: " << app << "\n";
                return;
            }
        }
        std::cerr << "[Rules] Unknown app: " << app << "\n";
    }
    void blockDomain(const std::string& dom) {
        blocked_domains.push_back(dom);
        std::cout << "[Rules] Blocked domain: " << dom << "\n";
    }
    void blockPort(uint16_t port) {
        blocked_ports.insert(port);
        std::cout << "[Rules] Blocked port: " << port << "\n";
    }

    bool isBlocked(uint32_t src_ip, uint16_t dst_port, AppType app,
                   const std::string& sni) const {
        if (blocked_ips.count(src_ip))    return true;
        if (blocked_ports.count(dst_port)) return true;
        if (blocked_apps.count(app))       return true;
        for (const auto& dom : blocked_domains) {
            if (!sni.empty() && sni.find(dom) != std::string::npos) return true;
        }
        return false;
    }

    // Feature 7: Load rules from file
    bool loadFromFile(const std::string& filename) {
        std::ifstream f(filename);
        if (!f.is_open()) {
            std::cerr << "[Rules] Cannot open rules file: " << filename << "\n";
            return false;
        }
        std::string line, section;
        while (std::getline(f, line)) {
            if (line.empty() || line[0] == '#') continue;
            if (line[0] == '[') { section = line; continue; }
            if (section == "[BLOCKED_IPS]")     blockIP(line);
            else if (section == "[BLOCKED_APPS]")    blockApp(line);
            else if (section == "[BLOCKED_DOMAINS]") blockDomain(line);
            else if (section == "[BLOCKED_PORTS]") {
                try { blockPort(static_cast<uint16_t>(std::stoi(line))); }
                catch (...) {}
            }
        }
        std::cout << "[Rules] Loaded rules from: " << filename << "\n";
        return true;
    }

private:
    static uint32_t parseIP(const std::string& ip) {
        uint32_t result = 0; int octet = 0, shift = 0;
        for (char c : ip) {
            if (c == '.') { result |= (octet << shift); shift += 8; octet = 0; }
            else if (c >= '0' && c <= '9') octet = octet * 10 + (c - '0');
        }
        return result | (octet << shift);
    }
};

// ============================================================
// Usage / Help
// ============================================================
void printUsage(const char* prog) {
    std::cout << R"(
DPI Engine v3.0 - Deep Packet Inspection System
================================================

Usage: )" << prog << R"( <input.pcap> <output.pcap> [options]

Filtering:
  --block-ip <ip>           Block source IP address
  --block-app <app>         Block application (YouTube, TikTok, Facebook...)
  --block-domain <domain>   Block domain (substring match)
  --block-port <port>       Block destination port
  --rules <file>            Load blocking rules from file

Reporting:
  --top <N>                 Print Top-N flows by bytes (default: 10)
  --export-json <file>      Export full report as JSON
  --export-csv  <file>      Export flow table as CSV
  --verbose                 Print every classified flow
  --quiet                   Suppress all output except final report

Examples:
  )" << prog << R"( cap.pcap out.pcap --block-app YouTube --top 5
  )" << prog << R"( cap.pcap out.pcap --rules rules.txt --export-json report.json
  )" << prog << R"( cap.pcap out.pcap --export-csv flows.csv
)";
}

// ============================================================
// IP to string helper
// ============================================================
static std::string ip32ToString(uint32_t ip) {
    char buf[20];
    snprintf(buf, sizeof(buf), "%u.%u.%u.%u",
             (ip >> 0) & 0xFF, (ip >> 8) & 0xFF,
             (ip >> 16) & 0xFF, (ip >> 24) & 0xFF);
    return buf;
}

// ============================================================
// Feature 5: JSON Export
// ============================================================
void exportJSON(const std::string& filename,
                const std::string& input_file,
                const std::string& output_file,
                uint64_t total, uint64_t forwarded, uint64_t dropped,
                const std::unordered_map<FiveTuple, Flow, FiveTupleHash>& flows) {
    std::ofstream f(filename);
    if (!f.is_open()) { std::cerr << "[JSON] Cannot open: " << filename << "\n"; return; }

    auto now = std::chrono::system_clock::now();
    std::time_t t = std::chrono::system_clock::to_time_t(now);
    char timebuf[64];
    strftime(timebuf, sizeof(timebuf), "%Y-%m-%dT%H:%M:%S", std::localtime(&t));

    // App stats
    std::unordered_map<AppType, uint64_t> app_stats;
    for (const auto& [tup, fl] : flows) app_stats[fl.app_type] += fl.packets;

    f << "{\n";
    f << "  \"generated\": \"" << timebuf << "\",\n";
    f << "  \"input\": \"" << input_file << "\",\n";
    f << "  \"output\": \"" << output_file << "\",\n";
    f << "  \"summary\": {\n";
    f << "    \"total_packets\": " << total << ",\n";
    f << "    \"forwarded\": " << forwarded << ",\n";
    f << "    \"dropped\": " << dropped << ",\n";
    f << "    \"active_flows\": " << flows.size() << "\n";
    f << "  },\n";

    // App distribution
    f << "  \"app_distribution\": {\n";
    bool first = true;
    for (const auto& [app, cnt] : app_stats) {
        if (!first) f << ",\n";
        f << "    \"" << appTypeToString(app) << "\": " << cnt;
        first = false;
    }
    f << "\n  },\n";

    // Flow table
    f << "  \"flows\": [\n";
    first = true;
    for (const auto& [tup, fl] : flows) {
        if (!first) f << ",\n";
        f << "    {\n";
        f << "      \"src_ip\": \"" << ip32ToString(tup.src_ip) << "\",\n";
        f << "      \"dst_ip\": \"" << ip32ToString(tup.dst_ip) << "\",\n";
        f << "      \"src_port\": " << tup.src_port << ",\n";
        f << "      \"dst_port\": " << tup.dst_port << ",\n";
        f << "      \"protocol\": " << (int)tup.protocol << ",\n";
        f << "      \"app\": \"" << appTypeToString(fl.app_type) << "\",\n";
        f << "      \"proto_label\": \"" << fl.proto_label << "\",\n";
        if (!fl.sni.empty())
            f << "      \"sni\": \"" << fl.sni << "\",\n";
        if (!fl.ja3.ja3_hex.empty())
            f << "      \"ja3\": \"" << fl.ja3.ja3_hex << "\",\n";
        f << "      \"packets\": " << fl.packets << ",\n";
        f << "      \"bytes\": " << fl.bytes << ",\n";
        f << "      \"blocked\": " << (fl.blocked ? "true" : "false") << "\n";
        f << "    }";
        first = false;
    }
    f << "\n  ]\n}\n";
    f.close();
    std::cout << "[JSON] Report exported to: " << filename << "\n";
}

// ============================================================
// Feature 6: CSV Export
// ============================================================
void exportCSV(const std::string& filename,
               const std::unordered_map<FiveTuple, Flow, FiveTupleHash>& flows) {
    std::ofstream f(filename);
    if (!f.is_open()) { std::cerr << "[CSV] Cannot open: " << filename << "\n"; return; }

    // Header
    f << "src_ip,dst_ip,src_port,dst_port,protocol,app,proto_label,sni,ja3,packets,bytes,blocked\n";

    for (const auto& [tup, fl] : flows) {
        f << ip32ToString(tup.src_ip) << ","
          << ip32ToString(tup.dst_ip) << ","
          << tup.src_port << ","
          << tup.dst_port << ","
          << (int)tup.protocol << ","
          << appTypeToString(fl.app_type) << ","
          << fl.proto_label << ","
          << fl.sni << ","
          << fl.ja3.ja3_hex << ","
          << fl.packets << ","
          << fl.bytes << ","
          << (fl.blocked ? "true" : "false") << "\n";
    }
    f.close();
    std::cout << "[CSV] Flow table exported to: " << filename << "\n";
}

// ============================================================
// Feature 4: Top-N Flow Reporter
// ============================================================
void printTopFlows(const std::unordered_map<FiveTuple, Flow, FiveTupleHash>& flows,
                   int n) {
    std::vector<const Flow*> sorted;
    sorted.reserve(flows.size());
    for (const auto& [tup, fl] : flows) sorted.push_back(&fl);
    std::sort(sorted.begin(), sorted.end(),
              [](const Flow* a, const Flow* b) { return a->bytes > b->bytes; });

    n = std::min(n, (int)sorted.size());
    std::cout << "\n╔══════════════════════════════════════════════════════════════╗\n";
    std::cout << "║                   TOP " << std::setw(2) << n << " FLOWS BY BYTES                         ║\n";
    std::cout << "╠═══════════════════════════╦════════╦═══════╦════════╦════════╣\n";
    std::cout << "║ Flow                      ║  App   ║  Pkts ║  Bytes ║ Status ║\n";
    std::cout << "╠═══════════════════════════╩════════╩═══════╩════════╩════════╣\n";
    for (int i = 0; i < n; i++) {
        const Flow* fl = sorted[i];
        std::string label = fl->sni.empty() ? fl->proto_label : fl->sni;
        if (label.empty()) label = appTypeToString(fl->app_type);
        if (label.size() > 26) label = label.substr(0, 23) + "...";
        std::cout << "║ " << std::setw(26) << std::left << label
                  << std::setw(7)  << std::right << appTypeToString(fl->app_type).substr(0,6)
                  << " " << std::setw(6) << fl->packets
                  << " " << std::setw(7) << fl->bytes
                  << " " << std::setw(7) << (fl->blocked ? "BLOCKED" : "OK") << " ║\n";
    }
    std::cout << "╚══════════════════════════════════════════════════════════════╝\n";
}

// ============================================================
// ASCII bar chart helper
// ============================================================
static std::string bar(double pct, int width = 20) {
    int filled = static_cast<int>(pct / 100.0 * width);
    return std::string(filled, '#') + std::string(width - filled, '.');
}

// ============================================================
// Main
// ============================================================
int main(int argc, char* argv[]) {
    if (argc < 3) { printUsage(argv[0]); return 1; }

    std::string input_file  = argv[1];
    std::string output_file = argv[2];

    // Option storage
    BlockingRules  rules;
    DNSCorrelator  dns_corr;
    std::string    json_out, csv_out;
    int            top_n   = 10;
    bool           verbose = false;
    bool           quiet   = false;

    // Parse CLI args
    for (int i = 3; i < argc; i++) {
        std::string arg = argv[i];
        if      (arg == "--block-ip"     && i+1 < argc) rules.blockIP(argv[++i]);
        else if (arg == "--block-app"    && i+1 < argc) rules.blockApp(argv[++i]);
        else if (arg == "--block-domain" && i+1 < argc) rules.blockDomain(argv[++i]);
        else if (arg == "--block-port"   && i+1 < argc) {
            try { rules.blockPort(static_cast<uint16_t>(std::stoi(argv[++i]))); }
            catch (...) {}
        }
        else if (arg == "--rules"        && i+1 < argc) rules.loadFromFile(argv[++i]);
        else if (arg == "--export-json"  && i+1 < argc) json_out = argv[++i];
        else if (arg == "--export-csv"   && i+1 < argc) csv_out  = argv[++i];
        else if (arg == "--top"          && i+1 < argc) {
            try { top_n = std::stoi(argv[++i]); } catch (...) {}
        }
        else if (arg == "--verbose") verbose = true;
        else if (arg == "--quiet")   quiet   = true;
    }

    if (!quiet) {
        std::cout << "\n";
        std::cout << "╔══════════════════════════════════════════════════════════════╗\n";
        std::cout << "║              DPI ENGINE v3.0  (Enhanced Edition)             ║\n";
        std::cout << "╚══════════════════════════════════════════════════════════════╝\n\n";
    }

    // Open input PCAP
    PcapReader reader;
    if (!reader.open(input_file)) return 1;

    // Open output PCAP
    std::ofstream output(output_file, std::ios::binary);
    if (!output.is_open()) {
        std::cerr << "Error: Cannot open output file: " << output_file << "\n";
        return 1;
    }

    // Write PCAP global header to output
    const auto& ghdr = reader.getGlobalHeader();
    output.write(reinterpret_cast<const char*>(&ghdr), sizeof(ghdr));

    // Flow table
    std::unordered_map<FiveTuple, Flow, FiveTupleHash> flows;

    // Stats
    uint64_t total_packets = 0, forwarded = 0, dropped = 0;
    std::unordered_map<AppType, uint64_t> app_stats;
    std::unordered_map<std::string, uint64_t> proto_label_stats;
    std::unordered_map<std::string, AppType>  sni_map;    // sni -> app
    std::unordered_map<std::string, uint64_t> ja3_seen;   // ja3 -> count

    if (!quiet) std::cout << "[DPI] Processing packets...\n";

    auto t_start = std::chrono::steady_clock::now();

    RawPacket raw;
    ParsedPacket parsed;

    while (reader.readNextPacket(raw)) {
        total_packets++;

        if (!PacketParser::parse(raw, parsed)) continue;
        if (!parsed.has_ip) continue;
        if (!parsed.has_tcp && !parsed.has_udp) continue;

        // Build five-tuple
        FiveTuple tuple;
        auto parseIPStr = [](const std::string& ip) -> uint32_t {
            uint32_t r = 0; int o = 0, s = 0;
            for (char c : ip) {
                if (c == '.') { r |= (o << s); s += 8; o = 0; }
                else if (c >= '0' && c <= '9') o = o*10 + (c-'0');
            }
            return r | (o << s);
        };
        tuple.src_ip   = parseIPStr(parsed.src_ip);
        tuple.dst_ip   = parseIPStr(parsed.dest_ip);
        tuple.src_port = parsed.src_port;
        tuple.dst_port = parsed.dest_port;
        tuple.protocol = parsed.protocol;

        Flow& flow = flows[tuple];
        if (flow.packets == 0) {
            flow.tuple      = tuple;
            flow.first_seen = std::chrono::steady_clock::now();
        }
        flow.packets++;
        flow.bytes    += raw.data.size();
        flow.last_seen = std::chrono::steady_clock::now();

        //  ---- Determine payload pointer ----
        size_t poff = 14;  // Ethernet
        if (poff < raw.data.size()) {
            uint8_t ihl = raw.data[poff] & 0x0F;
            poff += ihl * 4;
        }
        size_t payload_off = poff;
        if (parsed.has_tcp && payload_off + 12 < raw.data.size()) {
            uint8_t toff = (raw.data[payload_off + 12] >> 4) & 0x0F;
            payload_off += toff * 4;
        } else if (parsed.has_udp) {
            payload_off += 8;
        }
        const uint8_t* payload     = (payload_off < raw.data.size())
                                       ? raw.data.data() + payload_off : nullptr;
        size_t         payload_len = (payload && payload_off < raw.data.size())
                                       ? raw.data.size() - payload_off : 0;

        // ---- Feature 1: Extended Protocol Detection (port-based fallback) ----
        if (flow.proto_label.empty()) {
            std::string lbl = portToProtocolLabel(tuple.dst_port);
            if (lbl.empty()) lbl = portToProtocolLabel(tuple.src_port);
            flow.proto_label = lbl;
        }

        // ---- Feature 3: DNS Correlation ----
        if (parsed.has_udp && (tuple.dst_port == 53 || tuple.src_port == 53)
            && payload && payload_len > 12) {
            dns_corr.recordDNSQuery(payload, payload_len, tuple.src_ip);
            if (flow.app_type == AppType::UNKNOWN)
                flow.app_type = AppType::DNS;
        }

        // ---- SNI / Host extraction (HTTPS and HTTP) ----
        if (payload && payload_len > 5) {
            // Try TLS SNI
            if ((flow.app_type == AppType::UNKNOWN || flow.app_type == AppType::HTTPS)
                && flow.sni.empty() && parsed.has_tcp && tuple.dst_port == 443) {

                auto sni = SNIExtractor::extract(payload, payload_len);
                if (sni) {
                    flow.sni      = *sni;
                    flow.app_type = sniToAppType(*sni);
                    sni_map[*sni] = flow.app_type;
                    if (verbose && !quiet)
                        std::cout << "[SNI] " << *sni << " -> " << appTypeToString(flow.app_type) << "\n";
                }

                // Feature 2: JA3 fingerprint
                if (flow.ja3.empty()) {
                    flow.ja3 = extractJA3(payload, payload_len);
                    if (!flow.ja3.ja3_hex.empty())
                        ja3_seen[flow.ja3.ja3_hex]++;
                }
            }

            // HTTP Host header
            if ((flow.app_type == AppType::UNKNOWN || flow.app_type == AppType::HTTP)
                && flow.sni.empty() && parsed.has_tcp && tuple.dst_port == 80) {
                auto host = HTTPHostExtractor::extract(payload, payload_len);
                if (host) {
                    flow.sni      = *host;
                    flow.app_type = sniToAppType(*host);
                    sni_map[*host] = flow.app_type;
                }
            }
        }

        // ---- Feature 3: DNS correlation fallback for HTTPS ----
        if (flow.sni.empty() && tuple.dst_port == 443) {
            std::string correlated = dns_corr.correlate(tuple.src_ip, "");
            if (!correlated.empty()) {
                flow.sni      = correlated + " (dns-corr)";
                flow.app_type = sniToAppType(correlated);
            }
        }

        // ---- Port-based fallback for app type ----
        if (flow.app_type == AppType::UNKNOWN) {
            AppType pt = portToAppType(tuple.dst_port);
            if (pt != AppType::UNKNOWN) flow.app_type = pt;
            else flow.app_type = portToAppType(tuple.src_port);
        }

        // ---- Blocking check ----
        if (!flow.blocked) {
            flow.blocked = rules.isBlocked(tuple.src_ip, tuple.dst_port,
                                            flow.app_type, flow.sni);
            if (flow.blocked && !quiet) {
                std::cout << "[BLOCKED] " << parsed.src_ip << " -> " << parsed.dest_ip
                          << ":" << tuple.dst_port
                          << " (" << appTypeToString(flow.app_type);
                if (!flow.sni.empty()) std::cout << ": " << flow.sni;
                std::cout << ")\n";
            }
        }

        // ---- Stats ----
        app_stats[flow.app_type]++;
        if (!flow.proto_label.empty())
            proto_label_stats[flow.proto_label]++;

        // ---- Forward or Drop ----
        if (flow.blocked) {
            dropped++;
        } else {
            forwarded++;
            PcapPacketHeader phdr;
            phdr.ts_sec  = raw.header.ts_sec;
            phdr.ts_usec = raw.header.ts_usec;
            phdr.incl_len = static_cast<uint32_t>(raw.data.size());
            phdr.orig_len = static_cast<uint32_t>(raw.data.size());
            output.write(reinterpret_cast<const char*>(&phdr), sizeof(phdr));
            output.write(reinterpret_cast<const char*>(raw.data.data()), raw.data.size());
        }
    }

    reader.close();
    output.close();

    auto t_end   = std::chrono::steady_clock::now();
    double elapsed = std::chrono::duration<double>(t_end - t_start).count();

    // ============================================================
    // Final Report
    // ============================================================
    if (!quiet) {
        std::cout << "\n";
        std::cout << "╔══════════════════════════════════════════════════════════════╗\n";
        std::cout << "║                      PROCESSING REPORT                       ║\n";
        std::cout << "╠══════════════════════════════════════════════════════════════╣\n";
        std::cout << "║ Input:           " << std::setw(44) << std::left << input_file  << "║\n";
        std::cout << "║ Output:          " << std::setw(44) << std::left << output_file << "║\n";
        std::cout << "║ Duration:        " << std::setw(10) << std::fixed << std::setprecision(3)
                  << elapsed << " sec                                ║\n";
        std::cout << "╠══════════════════════════════════════════════════════════════╣\n";
        std::cout << "║ Total Packets:   " << std::setw(10) << std::right << total_packets
                  << "                                ║\n";
        std::cout << "║ Forwarded:       " << std::setw(10) << forwarded
                  << "                                ║\n";
        std::cout << "║ Dropped:         " << std::setw(10) << dropped
                  << "                                ║\n";
        std::cout << "║ Active Flows:    " << std::setw(10) << flows.size()
                  << "                                ║\n";
        std::cout << "╠══════════════════════════════════════════════════════════════╣\n";
        std::cout << "║                   APPLICATION BREAKDOWN                      ║\n";
        std::cout << "╠══════════════════════════════════════════════════════════════╣\n";

        // Sort by count desc
        std::vector<std::pair<AppType, uint64_t>> sorted_apps(app_stats.begin(), app_stats.end());
        std::sort(sorted_apps.begin(), sorted_apps.end(),
                  [](const auto& a, const auto& b) { return a.second > b.second; });

        for (const auto& [app, cnt] : sorted_apps) {
            double pct = total_packets > 0 ? 100.0 * cnt / total_packets : 0;
            std::string b = bar(pct, 18);
            std::cout << "║ " << std::setw(14) << std::left << appTypeToString(app)
                      << std::setw(7) << std::right << cnt
                      << " " << std::setw(5) << std::fixed << std::setprecision(1) << pct << "% "
                      << std::setw(18) << std::left << b << " ║\n";
        }

        // Protocol labels (Feature 1)
        if (!proto_label_stats.empty()) {
            std::cout << "╠══════════════════════════════════════════════════════════════╣\n";
            std::cout << "║                 PROTOCOL BREAKDOWN (by PORT)                 ║\n";
            std::cout << "╠══════════════════════════════════════════════════════════════╣\n";
            std::vector<std::pair<std::string, uint64_t>> sorted_protos(
                proto_label_stats.begin(), proto_label_stats.end());
            std::sort(sorted_protos.begin(), sorted_protos.end(),
                      [](const auto& a, const auto& b) { return a.second > b.second; });
            for (const auto& [lbl, cnt] : sorted_protos) {
                double pct = total_packets > 0 ? 100.0 * cnt / total_packets : 0;
                std::string b = bar(pct, 18);
                std::cout << "║ " << std::setw(14) << std::left << lbl
                          << std::setw(7) << std::right << cnt
                          << " " << std::setw(5) << std::fixed << std::setprecision(1) << pct << "% "
                          << std::setw(18) << std::left << b << " ║\n";
            }
        }

        // Detected SNIs
        if (!sni_map.empty()) {
            std::cout << "╠══════════════════════════════════════════════════════════════╣\n";
            std::cout << "║                   DETECTED DOMAINS/SNIs                      ║\n";
            std::cout << "╠══════════════════════════════════════════════════════════════╣\n";
            for (const auto& [sni, app] : sni_map) {
                std::string s = sni.size() > 40 ? sni.substr(0,37)+"..." : sni;
                std::cout << "║  " << std::setw(42) << std::left << s
                          << std::setw(16) << std::right << appTypeToString(app) << "  ║\n";
            }
        }

        // JA3 fingerprints (Feature 2)
        if (!ja3_seen.empty()) {
            std::cout << "╠══════════════════════════════════════════════════════════════╣\n";
            std::cout << "║              TLS JA3 FINGERPRINTS SEEN                       ║\n";
            std::cout << "╠══════════════════════════════════════════════════════════════╣\n";
            std::vector<std::pair<std::string, uint64_t>> ja3_sorted(ja3_seen.begin(), ja3_seen.end());
            std::sort(ja3_sorted.begin(), ja3_sorted.end(),
                      [](const auto& a, const auto& b) { return a.second > b.second; });
            for (const auto& [fp, cnt] : ja3_sorted) {
                std::cout << "║  " << std::setw(32) << std::left << fp
                          << " count: " << std::setw(6) << cnt << "                 ║\n";
            }
        }

        std::cout << "╚══════════════════════════════════════════════════════════════╝\n";

        // Feature 4: Top-N flows
        printTopFlows(flows, top_n);
    }

    // Feature 5: JSON export
    if (!json_out.empty())
        exportJSON(json_out, input_file, output_file,
                   total_packets, forwarded, dropped, flows);

    // Feature 6: CSV export
    if (!csv_out.empty())
        exportCSV(csv_out, flows);

    if (!quiet)
        std::cout << "\nOutput written to: " << output_file << "\n";

    return 0;
}
