<div align="center">

# Inspectra

### Deep Packet Inspection & Network Protocol Analysis Studio

[![Java](https://img.shields.io/badge/Java-17%2B-e76f00?logo=openjdk&logoColor=white)](https://openjdk.org/)
[![React](https://img.shields.io/badge/React-19-61dafb?logo=react&logoColor=black)](https://react.dev/)
[![Vite](https://img.shields.io/badge/Vite-8-646cff?logo=vite&logoColor=white)](https://vite.dev/)
[![TypeScript](https://img.shields.io/badge/TypeScript-6-3178c6?logo=typescript&logoColor=white)](https://www.typescriptlang.org/)
[![License](https://img.shields.io/badge/License-MIT-22c55e)](#license)

A high-performance network packet analyzer and Deep Packet Inspection (DPI) suite that reads raw PCAP captures at the byte level, decodes the full OSI protocol stack from Layer 2 through Layer 7, extracts encrypted application metadata such as TLS SNI hostnames, and classifies live network traffic with security anomaly detection — all without relying on any third-party packet libraries.

**Java Core Engine** · **Browser-Side PCAP Parser** · **Interactive Web Studio** · **Drag-and-Drop Upload**

[Quick Start](#-quick-start) · [How It Works](#-how-it-works--technical-deep-dive) · [Web Studio](#%EF%B8%8F-web-studio) · [Architecture](#-architecture) · [Interview Guide](#-interview-preparation-guide) · [Troubleshooting](#-troubleshooting)

</div>

---

## 🎯 Project Motivation & Problem Statement

Modern enterprise networks carry millions of packets per second across hundreds of applications. Standard firewalls operate at Layers 3–4 (IP addresses and ports) and **cannot distinguish between different applications running on the same port** — for example, both HTTPS web browsing and malicious command-and-control traffic use TCP port 443.

**Deep Packet Inspection (DPI)** solves this by looking *inside* the packet payload to identify the actual application-layer protocol and the specific service being accessed. This project implements a complete DPI pipeline from scratch:

1. **Binary PCAP file parsing** — reading raw capture files byte-by-byte without any external libraries
2. **Multi-layer protocol dissection** — decoding Ethernet → IPv4 → TCP/UDP headers using RFC-defined field offsets
3. **Application-layer metadata extraction** — walking TLS handshake structures to extract SNI, parsing HTTP headers, and decoding DNS question sections
4. **Traffic classification** — mapping extracted hostnames to known services via domain substring matching
5. **Security anomaly detection** — flagging suspicious traffic patterns like SYN flood attacks from blocked IPs

The project demonstrates practical knowledge of **computer networking**, **binary data processing**, **protocol engineering**, and **full-stack development**.

---

## ✨ Key Capabilities

### Multi-Layer Protocol Dissection

| OSI Layer | Protocol | What We Parse | Byte Offset Details |
| :--- | :--- | :--- | :--- |
| **L2 — Data Link** | Ethernet II | Source MAC (6 bytes), Destination MAC (6 bytes), EtherType (2 bytes) | Bytes `[0–5]` dst MAC, `[6–11]` src MAC, `[12–13]` EtherType |
| **L3 — Network** | IPv4 | Version, IHL, TTL, Protocol, Source IP, Destination IP | 20-byte minimum header; IHL field at `[0]` encodes header length as `IHL × 4` bytes |
| **L4 — Transport** | TCP | Src/Dst Ports, Sequence & Ack numbers, Flags (`SYN`, `ACK`, `PSH`, `FIN`, `RST`, `URG`) | 20-byte minimum header; Data Offset at byte `[12]` encodes TCP header length |
| | UDP | Src/Dst Ports, Datagram Length | Fixed 8-byte header |
| **L7 — Application** | TLS 1.0–1.3 | Client Hello SNI hostname extraction | Content type `0x16`, Handshake type `0x01`, Extension type `0x0000` |
| | HTTP/1.1 | Method detection + `Host:` header extraction | ASCII text parsing — matches `GET`, `POST`, `HEAD`, `PUT`, `DELETE`, `OPTIONS` |
| | DNS | Question section domain name extraction | Label-encoded domain names after 12-byte DNS header, UDP port 53 |

### Service Classification Engine

Extracted hostnames and domains are mapped to **16+ known services** via case-insensitive substring matching against a curated domain dictionary:

| Service | Domain Pattern | Service | Domain Pattern |
| :--- | :--- | :--- | :--- |
| Google | `*google*` | Discord | `*discord*` |
| YouTube | `*youtube*` | Telegram | `*telegram*` |
| Facebook | `*facebook*` | TikTok | `*tiktok*` |
| Instagram | `*instagram*` | Spotify | `*spotify*` |
| Twitter / X | `*twitter*`, `*x.com*` | Zoom | `*zoom*` |
| Netflix | `*netflix*` | Cloudflare | `*cloudflare*` |
| Amazon | `*amazon*` | Microsoft | `*microsoft*` |
| GitHub | `*github*` | Apple | `*apple*` |

### Security & Anomaly Detection

The engine flags **SYN flood patterns** from known blocked IPs (e.g., `192.168.1.50`). SYN floods work by sending massive numbers of TCP SYN packets without completing the three-way handshake, exhausting the server's connection table. The Web Studio highlights these packets with red visual indicators.

---

## 🔬 How It Works — Technical Deep Dive

### 1. PCAP File Format Parsing

The [PCAP file format](https://wiki.wireshark.org/Development/LibpcapFileFormat) is a binary format used by Wireshark, tcpdump, and virtually all packet capture tools. Our parser (`PcapReader.java` / `pcapParser.ts`) reads it from scratch:

```
┌───────────────────────────────────────────────┐
│            PCAP Global Header (24 bytes)      │
│  Magic Number (4B) │ Version (4B) │ ...       │
│  Snap Length (4B)  │ Link Type (4B)           │
├───────────────────────────────────────────────┤
│            Packet Header #1 (16 bytes)        │
│  Timestamp Sec (4B) │ Timestamp µSec (4B)     │
│  Captured Length (4B) │ Original Length (4B)   │
├───────────────────────────────────────────────┤
│            Packet Data #1 (variable)          │
│  [Ethernet][IP][TCP/UDP][Payload...]          │
├───────────────────────────────────────────────┤
│            Packet Header #2 (16 bytes)        │
│            Packet Data #2 (variable)          │
│                    ...                        │
└───────────────────────────────────────────────┘
```

**Key implementation details:**

- **Magic number detection** (`0xa1b2c3d4` native vs. `0xd4c3b2a1` swapped) determines the file's **byte order** (little-endian vs. big-endian). The parser tries both orderings before rejecting the file.
- All multi-byte integers are read with explicit `ByteOrder` (Java) or `DataView` littleEndian flag (TypeScript) to handle endianness correctly.
- Packet data is bounded by `inclLen` (captured length), which may be less than `origLen` (original wire length) if the capture was truncated by the snap length.

### 2. Ethernet Frame Parsing (Layer 2)

Every packet begins with a 14-byte Ethernet II header:

```
Bytes:  [0-5]         [6-11]        [12-13]
Field:  Dest MAC      Source MAC    EtherType
        6 bytes       6 bytes       2 bytes (Big Endian)
```

The **EtherType** field determines what Layer 3 protocol follows:
- `0x0800` → IPv4 (most common, what we parse)
- `0x86DD` → IPv6
- `0x0806` → ARP

MAC addresses are formatted as colon-separated hex pairs (e.g., `00:11:22:33:44:55`).

### 3. IPv4 Header Parsing (Layer 3)

The IPv4 header is a minimum of 20 bytes but can be longer if IP options are present:

```
Byte 0:   [Version (4 bits)][IHL (4 bits)]     ← IHL × 4 = header length in bytes
Byte 8:   TTL (Time to Live)
Byte 9:   Protocol                              ← 6 = TCP, 17 = UDP, 1 = ICMP
Byte 12:  Source IP (4 bytes)
Byte 16:  Destination IP (4 bytes)
```

**Why IHL matters:** The IHL (Internet Header Length) field tells us exactly where the IPv4 header ends and the transport layer begins. A value of `5` means 20 bytes (the minimum). A value of `6` means 24 bytes (with 4 bytes of options). Skipping the wrong number of bytes would cause the TCP/UDP parser to read garbage data.

### 4. TCP Header Parsing (Layer 4)

```
Bytes 0-1:   Source Port (Big Endian)
Bytes 2-3:   Destination Port (Big Endian)
Bytes 4-7:   Sequence Number (32-bit unsigned)
Bytes 8-11:  Acknowledgment Number (32-bit unsigned)
Byte 12:     [Data Offset (4 bits)][Reserved]   ← Data Offset × 4 = header length
Byte 13:     Flags [URG|ACK|PSH|RST|SYN|FIN]
```

**TCP Flags decoded via bitmask:**
```java
TCP_FIN = 0x01,  TCP_SYN = 0x02,  TCP_RST = 0x04
TCP_PSH = 0x08,  TCP_ACK = 0x10,  TCP_URG = 0x20
```
Each flag is extracted using a bitwise AND: `(flags & TCP_SYN) != 0`.

The **Data Offset** field is critical — it tells us where the TCP payload (and thus the application data) begins. Like IHL in IPv4, it's measured in 4-byte words.

### 5. TLS Client Hello SNI Extraction (Layer 7 — DPI)

This is the core DPI capability. When a browser connects to `https://www.google.com`, the very first TLS message is a **Client Hello** that contains the hostname in plaintext inside the **Server Name Indication (SNI)** extension — even though the rest of the session is encrypted.

**Our parsing algorithm walks through the TLS structure byte-by-byte:**

```
Step 1: Verify TLS Record Header
  ├── Byte [0] == 0x16 (Content Type: Handshake)
  ├── Bytes [1-2] = TLS Version (0x0300 – 0x0304)
  └── Bytes [3-4] = Record Length

Step 2: Verify Handshake Type
  └── Byte [5] == 0x01 (Client Hello)

Step 3: Skip Fixed Fields
  ├── Skip 4 bytes (handshake header)
  ├── Skip 2 bytes (client version)
  ├── Skip 32 bytes (client random)
  ├── Read 1 byte (session ID length), skip that many bytes
  ├── Read 2 bytes (cipher suites length), skip that many bytes
  └── Read 1 byte (compression length), skip that many bytes

Step 4: Walk the Extensions Block
  ├── Read 2 bytes (total extensions length)
  └── Loop through each extension:
      ├── Read 2 bytes (extension type)
      ├── Read 2 bytes (extension data length)
      └── If extension type == 0x0000 (SNI):
          ├── Read 2 bytes (SNI list length)
          ├── Read 1 byte (SNI type — must be 0 for hostname)
          ├── Read 2 bytes (SNI string length)
          └── Read N bytes → ASCII hostname string ✓
```

**Why this matters for interviews:** This demonstrates understanding of binary protocol parsing, TLS handshake mechanics, and why SNI is visible even in encrypted connections (it's sent *before* encryption is established, which is why ECH — Encrypted Client Hello — was proposed in TLS 1.3).

### 6. HTTP Host Header Extraction

For unencrypted HTTP traffic, the parser reads the first 1024 bytes of the TCP payload as ISO-8859-1 text and:
1. Validates that the payload starts with an HTTP method (`GET`, `POST`, `HEAD`, `PUT`, `DELETE`, `OPTIONS`)
2. Scans for the `Host:` header line
3. Extracts the hostname, stripping any port suffix

### 7. DNS Query Domain Extraction

DNS packets on UDP port 53 encode domain names using **label encoding**:

```
www.google.com  →  [3]www[6]google[3]com[0]
                    ↑           ↑         ↑
               length byte  length byte  null terminator
```

The parser reads each label length byte, extracts that many ASCII characters, joins them with dots, and stops at the null terminator (`0x00`) or if a label exceeds 63 bytes (the DNS maximum label length).

### 8. Dual-Engine Architecture

The project has **two independent parsers** that implement the same algorithms:

| Engine | Language | Runtime | Use Case |
| :--- | :--- | :--- | :--- |
| **Java CLI Engine** | Java 17+ | JVM | Command-line analysis, batch processing, summary statistics |
| **Browser Parser** | TypeScript | Browser (WebAssembly-ready) | Real-time interactive analysis via drag-and-drop in the Web Studio |

Both parsers produce identical results — the Java engine uses `ByteBuffer` with explicit `ByteOrder`, while the TypeScript parser uses `DataView` and `Uint8Array` with the littleEndian flag. This demonstrates the same algorithm implemented idiomatically in two different languages.

---

## 📋 Prerequisites

| Tool | Version | Purpose |
| :--- | :--- | :--- |
| **Java JDK** | 17 + | Core DPI engine compilation & execution |
| **Node.js** | 18 + | Web Studio dev server |
| **npm** | 9 + | Frontend dependency management |
| **Python** | 3.8 + | *(Optional)* Synthetic PCAP generation via `generate_test_pcap.py` |

---

## 🚀 Quick Start

> [!IMPORTANT]
> On Windows, ensure your terminal is in the project root:
> ```cmd
> E:
> cd \Projects\deep_packet_inspection-main
> ```

### Option 1 — Web Studio Dashboard *(Recommended)*

```cmd
launch.bat web
```

Open **[http://localhost:5174/](http://localhost:5174/)** in your browser.

<details>
<summary>Or launch manually with npm</summary>

```bash
cd web
npm install   # first time only
npm run dev
```
</details>

### Option 2 — Java CLI Analyzer

```cmd
launch.bat            # analyze the default capture
launch.bat 10         # limit output to the first 10 packets
```

### Option 3 — PowerShell Launcher

```powershell
.\launch.ps1
.\launch.ps1 -PcapFile "deep_packet_inspection-main\test_dpi.pcap" -MaxPackets 15
```

### Option 4 — Direct Java Compilation

```cmd
cd deep_packet_inspection-main
javac -d src/main/java src/main/java/com/packetanalyzer/*.java
java -cp src/main/java com.packetanalyzer.Main test_dpi.pcap
```

---

## 🖥️ Web Studio

The interactive dashboard provides **Wireshark-grade packet inspection entirely in the browser** — no backend, no server-side processing. The PCAP file is parsed client-side using the TypeScript binary parser.

### Feature Breakdown

| Feature | Description | Technical Detail |
| :--- | :--- | :--- |
| **KPI Metrics Bar** | Total packets, payload volume, identified applications, TCP/UDP ratio, anomaly alerts | Computed via `useMemo` over the full packet array for O(n) aggregation |
| **Service Classification Chips** | One-click filter chips for every classified service | Derived from `appType` field; click toggles `selectedApp` state filter |
| **Search & Filters** | Full-text search across IPs, ports, SNI, DNS, payload + protocol tabs | Multi-field fuzzy match on every packet property; debounced re-render |
| **Packet Table** | Color-coded protocol tags, millisecond timestamps, source/dest addressing | Conditional CSS classes: `badge-tls`, `badge-http`, `badge-dns`, `badge-tcp`, `badge-udp` |
| **Deep Inspector Drawer** | Expandable tree dissecting L2 → L3 → L4 → L7 for the selected packet | Right-panel aside with card-based layer visualization |
| **Hex / ASCII Viewer** | 16-byte hex grouping with address offsets and one-click clipboard copy | Uses `navigator.clipboard.writeText()` with a 2-second "Copied!" indicator |
| **PCAP Drag & Drop** | Drop any `.pcap` file into the browser for instant parsing | `FileReader.readAsArrayBuffer()` → `parsePcapArrayBuffer()` pipeline |
| **Export** | Download filtered datasets as JSON or CSV | Client-side Blob generation with `encodeURIComponent` data URIs |

### Design System

- **Theme**: Obsidian / Cyber dark mode with CSS custom properties for all color tokens
- **Typography**: Inter (UI), JetBrains Mono (code/hex), Outfit (headings) — loaded via Google Fonts
- **Glass morphism**: Frosted-glass panels using `backdrop-filter: blur()` and semi-transparent backgrounds
- **Iconography**: Lucide React icon library (tree-shakeable, MIT-licensed)

---

## 🧪 Synthetic Test Capture Generator

The repository includes a Python script that **builds a valid PCAP file from scratch** — constructing every byte of every protocol header manually:

```bash
python deep_packet_inspection-main/generate_test_pcap.py
```

### What the generator builds (77 packets total)

| Traffic Type | Count | Details |
| :--- | :--- | :--- |
| **TLS with SNI** | 16 connections (64 pkts) | Full TCP 3-way handshake (SYN → SYN-ACK → ACK) + Client Hello with SNI for 16 domains |
| **HTTP/1.1** | 2 connections (4 pkts) | TCP SYN + HTTP GET request with `Host:` header for `example.com` and `httpbin.org` |
| **DNS** | 4 queries (4 pkts) | Standard UDP port-53 DNS queries with label-encoded domain names |
| **Anomalous** | 5 SYN floods (5 pkts) | SYN-only packets from blocked IP `192.168.1.50` — no handshake completion |

### How the generator works

The generator manually constructs binary protocol headers using Python's `struct.pack()`:

1. **PCAP Global Header**: Writes magic number `0xa1b2c3d4`, version 2.4, snap length 65535, link type 1 (Ethernet)
2. **Ethernet frames**: Packs 6-byte MAC addresses and 2-byte EtherType in big-endian
3. **IPv4 headers**: Sets `version_ihl = 0x45` (version 4, IHL 5), TTL 64, correct protocol number (6 for TCP, 17 for UDP)
4. **TCP headers**: Constructs with source/dest ports, sequence/ack numbers, and appropriate flag bytes (`0x02` = SYN, `0x12` = SYN-ACK, `0x10` = ACK, `0x18` = PSH-ACK)
5. **TLS Client Hello**: Builds the complete TLS record layer → handshake layer → extension block with SNI, including cipher suites and supported versions extension
6. **DNS queries**: Encodes domain names in label format (`[3]www[6]google[3]com[0]`) with type A, class IN

---

## 🏗 Architecture

### System Architecture Diagram

```
┌────────────────────────────────────────────────────────────────────┐
│                        User Interface                              │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │        React 19 Web Studio (Vite 8 + TypeScript 6)          │  │
│  │  ┌─────────┐  ┌──────────┐  ┌────────┐  ┌───────────────┐  │  │
│  │  │  KPI    │  │  Packet  │  │ Search │  │  Deep Packet  │  │  │
│  │  │  Cards  │  │  Table   │  │& Filter│  │  Inspector    │  │  │
│  │  └─────────┘  └──────────┘  └────────┘  │  ┌──────────┐ │  │  │
│  │                                          │  │ Hex/ASCII│ │  │  │
│  │  ┌──────────────────────────────────┐   │  │ Viewer   │ │  │  │
│  │  │  Drag & Drop PCAP Upload Zone    │   │  └──────────┘ │  │  │
│  │  └──────────────────────────────────┘   └───────────────┘  │  │
│  └────────────────────────────┬─────────────────────────────────┘  │
│                               │                                    │
│                    ┌──────────▼──────────┐                         │
│                    │  pcapParser.ts      │  ← Browser-side binary  │
│                    │  (TypeScript PCAP   │     PCAP parser          │
│                    │   Binary Parser)    │                          │
│                    └────────────────────┘                          │
└────────────────────────────────────────────────────────────────────┘

┌────────────────────────────────────────────────────────────────────┐
│                     Java CLI Engine                                │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────────┐ │
│  │ PcapReader   │→ │ PacketParser │→ │ Main (CLI Output +       │ │
│  │ (Binary I/O) │  │ (L2–L7 DPI) │  │       Statistics)        │ │
│  └──────────────┘  └──────────────┘  └──────────────────────────┘ │
└────────────────────────────────────────────────────────────────────┘

┌────────────────────────────────────────────────────────────────────┐
│                     Test Infrastructure                            │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │  generate_test_pcap.py — Python PCAP generator              │  │
│  │  Builds 77-packet capture with TLS/HTTP/DNS/Anomaly traffic │  │
│  └──────────────────────────────────────────────────────────────┘  │
└────────────────────────────────────────────────────────────────────┘
```

### File Structure

```
Inspectra/
│
├── launch.bat                          # Windows one-click launcher (CLI & Web)
├── launch.ps1                          # PowerShell launcher with parameter support
├── README.md                           # This file
├── LICENSE                             # MIT License
├── .gitignore                          # Root gitignore (Java + Node + OS)
│
├── deep_packet_inspection-main/        # ──── Java DPI Engine ────
│   ├── generate_test_pcap.py           # Python synthetic PCAP generator
│   ├── test_dpi.pcap                   # Default 77-packet test capture
│   └── src/main/java/com/packetanalyzer/
│       ├── Main.java                   # CLI entry point — reads PCAP, prints results, aggregates stats
│       ├── PcapReader.java             # Binary PCAP stream reader — magic detection, endianness, packet iteration
│       ├── PacketParser.java           # Multi-layer parser — Ethernet, IPv4, TCP, UDP, and L7 DPI
│       ├── ParsedPacket.java           # Data model — all fields from L2 through L7 DPI results
│       ├── PcapGlobalHeader.java       # PCAP global header struct (magic, version, snaplen, link type)
│       ├── PcapPacketHeader.java       # Per-packet header struct (timestamp, captured/original length)
│       └── RawPacket.java              # Raw byte wrapper — header + data bytes
│
└── web/                                # ──── React Web Studio ────
    ├── package.json                    # React 19, Vite 8, TypeScript 6, Lucide React
    ├── vite.config.ts                  # Dev server on port 5174
    ├── index.html                      # Entry point with SEO meta, Google Fonts (Inter, JetBrains Mono, Outfit)
    └── src/
        ├── App.tsx                     # Main dashboard — 749 lines: KPIs, table, inspector, drag-drop, export
        ├── App.css                     # Obsidian/Cyber dark theme — packet table, badges, glass panels
        ├── index.css                   # Design tokens, CSS custom properties, glassmorphism utilities
        ├── utils/pcapParser.ts         # Browser-side binary PCAP parser — mirrors Java engine logic
        └── data/samplePcap.json        # Pre-parsed default capture for instant load
```

---

## 🎓 Interview Preparation Guide

### Networking & Protocols

<details>
<summary><strong>Q: What is Deep Packet Inspection (DPI) and how does it differ from regular packet filtering?</strong></summary>

**Regular packet filtering** (Layer 3–4) examines only IP addresses, ports, and protocol numbers. A firewall rule like "block TCP port 443" would block ALL HTTPS traffic indiscriminately.

**Deep Packet Inspection** goes further by examining the **payload content** at Layer 7. DPI can:
- Identify that TCP port 443 traffic to `www.youtube.com` is YouTube streaming vs. traffic to `malware-c2.evil.com` is a command-and-control channel
- Detect specific applications even when they use standard ports
- Extract metadata like TLS SNI hostnames, HTTP headers, and DNS queries

In this project, the `inspectPayload()` method in `PacketParser.java` performs DPI by sequentially attempting TLS SNI extraction, HTTP Host parsing, and DNS query decoding on the TCP/UDP payload.
</details>

<details>
<summary><strong>Q: Explain the TCP three-way handshake and how you see it in the PCAP data.</strong></summary>

The TCP three-way handshake establishes a reliable connection:

1. **SYN** (client → server): Client sends a packet with only the SYN flag set (`flags = 0x02`), proposing an initial sequence number
2. **SYN-ACK** (server → client): Server responds with both SYN and ACK flags (`flags = 0x12`), acknowledging the client's SYN and proposing its own sequence number
3. **ACK** (client → server): Client acknowledges the server's SYN with ACK flag (`flags = 0x10`)

In our test capture, every TLS connection starts with exactly these three packets before the Client Hello. The `generate_test_pcap.py` creates them explicitly:
```python
tcp_syn     = create_tcp_header(src_port, dst_port, seq, 0, 0x02)      # SYN
tcp_synack  = create_tcp_header(dst_port, src_port, seq+1000, seq+1, 0x12)  # SYN-ACK
tcp_ack     = create_tcp_header(src_port, dst_port, seq+1, seq+1001, 0x10)  # ACK
```

The anomaly traffic (SYN flood from `192.168.1.50`) only sends SYN packets — the handshake is never completed, which is what makes it a denial-of-service attack.
</details>

<details>
<summary><strong>Q: Why can you see the hostname even in HTTPS (encrypted) traffic?</strong></summary>

TLS encryption doesn't begin until *after* the handshake completes. The **Client Hello** message — which contains the SNI (Server Name Indication) extension — is sent in **plaintext** during the handshake, before any encryption keys are derived.

SNI exists because a single IP address can host multiple HTTPS websites (virtual hosting). The server needs to know which certificate to present *before* encryption starts. This is why:
- ISPs and firewalls can see which websites you visit even with HTTPS
- The newer **Encrypted Client Hello (ECH)** extension in TLS 1.3 was proposed to encrypt the SNI
- Our DPI engine exploits this by reading bytes at specific offsets within the TLS Client Hello structure

The `extractTlsSni()` method navigates: `TLS Record Header (5B) → Handshake Header (4B) → Client Version (2B) → Random (32B) → Session ID (variable) → Cipher Suites (variable) → Compression (variable) → Extensions → SNI Extension (type 0x0000)`.
</details>

<details>
<summary><strong>Q: How does DNS label encoding work?</strong></summary>

DNS does not store domain names as simple dot-separated strings. Instead, it uses **label encoding**:

```
www.google.com → [03]www[06]google[03]com[00]
```

Each label is preceded by a 1-byte length field (max 63), and the entire name is terminated by a zero byte. The maximum total domain name length is 253 characters.

Our parser in `extractDnsQuery()` reads this format:
```java
while (offset < length) {
    int labelLen = payload[offset] & 0xFF;
    if (labelLen == 0) break;        // null terminator
    if (labelLen > 63) break;        // invalid label
    offset++;
    domain.append(new String(payload, offset, labelLen, US_ASCII));
    offset += labelLen;
}
```

If a label length byte has the top two bits set (`0xC0`), it indicates **DNS compression** (a pointer to a previous label). Our parser stops at compressed labels since we only need the first query.
</details>

<details>
<summary><strong>Q: What is byte order (endianness) and why does it matter for packet parsing?</strong></summary>

**Big-endian** (network byte order): Most significant byte first. All network protocols (IP, TCP, UDP, DNS, TLS) use big-endian for multi-byte fields.

**Little-endian**: Least significant byte first. x86/x64 processors and most PCAP files use little-endian.

In our code, we handle this explicitly:
- **PCAP file headers**: Read in the byte order indicated by the magic number (`0xa1b2c3d4` = native, `0xd4c3b2a1` = swapped)
- **Protocol headers (Ethernet, IP, TCP, UDP)**: Always parsed as **big-endian** (`ByteOrder.BIG_ENDIAN` in Java, `false` for DataView's littleEndian parameter in TypeScript)

Getting this wrong would cause port numbers to be swapped (e.g., port 443 = `0x01BB` would be misread as `0xBB01` = 47873).
</details>

<details>
<summary><strong>Q: What is a SYN flood attack and how does this project detect it?</strong></summary>

A **SYN flood** is a denial-of-service (DoS) attack where the attacker sends many TCP SYN packets without completing the three-way handshake. Each SYN causes the server to allocate resources for a half-open connection. When thousands arrive per second, the server's connection table fills up and legitimate users can't connect.

**Detection in this project:**
- The Web Studio checks if `srcIp === '192.168.1.50'` (a known blocked IP) and flags those packets as anomalous
- These packets have `flags = 0x02` (SYN only) with no corresponding ACK — the hallmark of a SYN flood
- In the UI, anomalous packets are highlighted with red row backgrounds and a "Security Alerts" KPI card shows the count

In production DPI systems, SYN flood detection uses rate-based analysis (e.g., >100 SYN packets/second from a single source without corresponding SYN-ACKs).
</details>

### System Design & Architecture

<details>
<summary><strong>Q: Why did you implement two separate parsers (Java and TypeScript)?</strong></summary>

Each serves a distinct purpose:

1. **Java CLI Engine** — Designed for **batch processing and server-side analysis**. Reads PCAP files from disk using `FileInputStream`, processes packets sequentially, and outputs structured text reports with aggregate statistics. Ideal for automated pipelines, CI/CD analysis, or headless environments.

2. **TypeScript Browser Parser** — Designed for **interactive client-side analysis**. Uses `FileReader.readAsArrayBuffer()` to read files dropped into the browser, parses them using `DataView` and `Uint8Array`, and feeds results directly into React state for real-time rendering. No server round-trip needed.

Both implement the exact same DPI algorithms, demonstrating that **protocol parsing is language-agnostic** — the byte offsets, field sizes, and endianness rules are defined by RFCs, not by any programming language.
</details>

<details>
<summary><strong>Q: How does the browser-side parser handle binary data without Node.js?</strong></summary>

Modern browsers provide native APIs for binary data manipulation:

- **`ArrayBuffer`**: Raw binary data buffer (analogous to `byte[]` in Java)
- **`DataView`**: Provides typed access with explicit endianness control (`getUint32(offset, littleEndian)`)
- **`Uint8Array`**: Byte-level array view for per-byte access and slicing
- **`TextDecoder`**: Converts byte arrays to strings with specified encodings (ASCII, Latin-1)

The `parsePcapArrayBuffer()` function takes an `ArrayBuffer` from `FileReader.readAsArrayBuffer()`, wraps it in a `DataView` for endian-aware reads, and iterates through packet records exactly like the Java version — just with different API calls.
</details>

<details>
<summary><strong>Q: How does the React Web Studio manage state efficiently?</strong></summary>

The Web Studio uses React 19 with several optimization patterns:

1. **`useMemo` for derived state**: KPI analytics, filtered packets, and selected packet lookup are all memoized with appropriate dependency arrays to avoid recalculation on every render
2. **`useCallback` for event handlers**: The file upload handler is wrapped in `useCallback` to maintain referential stability
3. **Controlled filter state**: Protocol filter, search query, app filter, and selected packet ID are independent `useState` hooks that compose via the filtering pipeline
4. **No external state library**: The app's state is simple enough that React's built-in hooks suffice — no Redux, Zustand, or Context API needed

The filtering pipeline is: `packets → protocolFilter → appFilter → searchQuery → filteredPackets → display`.
</details>

### Data Structures & Algorithms

<details>
<summary><strong>Q: What is the time complexity of parsing a PCAP file with N packets?</strong></summary>

- **Overall parsing**: **O(N × P)** where N is the number of packets and P is the average packet payload size
- **Ethernet/IPv4/TCP/UDP header parsing**: **O(1)** per packet — fixed-offset field reads
- **TLS SNI extraction**: **O(E)** where E is the total extensions length — we walk through extensions linearly until we find type `0x0000`
- **HTTP Host extraction**: **O(min(P, 1024))** — we scan at most the first 1024 bytes for the `Host:` header
- **DNS query extraction**: **O(D)** where D is the domain name length — we read labels until the null terminator
- **Service classification**: **O(S)** where S is the number of service patterns (currently 18) — linear scan through substring matches
- **KPI computation in the Web Studio**: **O(N)** via `useMemo` — single pass over all packets
- **Filtering**: **O(N)** — every packet is tested against the active filters

Space complexity is **O(N)** — we store all parsed packets in memory.
</details>

<details>
<summary><strong>Q: How does the parser handle malformed or truncated packets?</strong></summary>

Every parsing function performs **bounds checking before every read**:

```java
// Example from parseTCP():
if (len < offset[0] + 20) return false;  // Need at least 20 bytes for TCP header

// Example from extractTlsSni():
if (length < 9) return null;                    // Minimum TLS record
if (offset + 2 > length) return null;           // Check before every field read
if (offset + extLen > extEnd) break;            // Extension overflows record
```

If any bounds check fails, the parser returns `false`/`null` and the packet is either skipped or displayed with whatever layers were successfully parsed (e.g., an IP packet with a truncated TCP header will still show L2 and L3 data).

The TypeScript parser wraps the entire TLS extraction in a `try-catch` block as an additional safety net against malformed data.
</details>

---

## 🔧 Troubleshooting

<details>
<summary><strong><code>launch.bat</code> is not recognized</strong></summary>

Ensure your terminal is inside the project root:
```cmd
E:
cd \Projects\deep_packet_inspection-main
```
</details>

<details>
<summary><strong>Port 5173 already in use</strong></summary>

The Web Studio is preconfigured to bind to **port 5174** to avoid collisions. If 5174 is also taken, edit `vite.config.ts` and set a free port.
</details>

<details>
<summary><strong>PowerShell blocks script execution</strong></summary>

Either use `launch.bat` in Command Prompt, or bypass the policy for a single run:
```powershell
powershell -ExecutionPolicy Bypass -File .\launch.ps1
```
</details>

<details>
<summary><strong>Java compilation fails</strong></summary>

Ensure `javac` and `java` are on your PATH:
```cmd
javac --version
java --version
```
If not, install JDK 17+ and add `JAVA_HOME/bin` to your system PATH.
</details>

---

## 🛣️ Future Scope

- [ ] **IPv6 support** — Extend L3 parsing to handle IPv6 40-byte headers and extension headers
- [ ] **QUIC / HTTP/3 dissection** — Parse UDP-based QUIC Initial packets to extract SNI
- [ ] **Connection tracking** — Reassemble TCP streams across multiple packets for full payload reconstruction
- [ ] **Rate-based anomaly detection** — Detect SYN floods, port scans, and DNS tunneling using packet rate thresholds
- [ ] **Protocol statistics dashboard** — Charts and graphs for traffic distribution, top talkers, and timeline visualization
- [ ] **Export to Wireshark** — Generate PCAP output files with filtered packet subsets
- [ ] **PCAPNG support** — Parse the newer PCAP Next Generation format with interface metadata

---

## 📄 License

This project is released under the **MIT License**. See [LICENSE](LICENSE) for details.

---

<div align="center">
  <sub>Built with ☕ Java, ⚛ React, and 🔍 curiosity.</sub>
</div>
