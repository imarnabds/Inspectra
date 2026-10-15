<div align="center">

# DeepPacket.AI

### Deep Packet Inspection & Network Protocol Studio

[![Java](https://img.shields.io/badge/Java-17%2B-e76f00?logo=openjdk&logoColor=white)](https://openjdk.org/)
[![React](https://img.shields.io/badge/React-19-61dafb?logo=react&logoColor=black)](https://react.dev/)
[![Vite](https://img.shields.io/badge/Vite-8-646cff?logo=vite&logoColor=white)](https://vite.dev/)
[![TypeScript](https://img.shields.io/badge/TypeScript-6-3178c6?logo=typescript&logoColor=white)](https://www.typescriptlang.org/)
[![License](https://img.shields.io/badge/License-MIT-22c55e)](#license)

A high-performance network packet analyzer and DPI suite that parses raw PCAP captures, decodes multi-layer protocol headers, extracts Layer-7 application metadata (TLS SNI, HTTP Host, DNS queries), and classifies traffic with security anomaly detection.

**Java Core Engine** · **Interactive Web Studio** · **Drag-and-Drop PCAP Upload**

[Quick Start](#-quick-start) · [Web Studio](#%EF%B8%8F-web-studio) · [Architecture](#-architecture) · [Troubleshooting](#-troubleshooting)

</div>

---

## ✨ Key Capabilities

### Protocol Dissection

| Layer | Scope | Details |
| :--- | :--- | :--- |
| **L2 — Data Link** | Ethernet II | Source / Destination MAC, EtherType (`0x0800` IPv4, `0x86dd` IPv6, `0x0806` ARP) |
| **L3 — Network** | IPv4 | Header validation, TTL, protocol field, source & destination IP |
| **L4 — Transport** | TCP | Ports, Seq / Ack numbers, flag decode (`SYN` `ACK` `PSH` `FIN` `RST` `URG`) |
| | UDP | Ports, datagram length validation |
| **L7 — Application (DPI)** | TLS | Client Hello SNI extraction across TLS 1.0 – 1.3 |
| | HTTP | Method detection (`GET`, `POST`, `HEAD`, …) and `Host` header extraction |
| | DNS | UDP port-53 question-section decoding and domain query extraction |

### Service Classification

Maps extracted hostnames and domains to **16+ known services** — Google, YouTube, Facebook, Twitter / X, Netflix, Amazon, GitHub, Discord, Telegram, TikTok, Spotify, Zoom, Cloudflare, Microsoft, Apple, HTTPBin, and more.

### Security & Anomaly Detection

Flags suspicious traffic patterns, anomalous source addresses, and simulated SYN floods (e.g., from blocked IP `192.168.1.50`).

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
> On Windows, make sure your terminal is in the project root:
> ```cmd
> E:
> cd \Projects\deep_packet_inspection-main
> ```

### Option 1 — Web Studio Dashboard *(Recommended)*

```cmd
launch.bat web
```

Then open **[http://localhost:5174/](http://localhost:5174/)** in your browser.

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

The interactive dashboard provides Wireshark-grade inspection entirely in the browser.

| Feature | Description |
| :--- | :--- |
| **KPI Metrics Bar** | Total packets, inspected payload volume, identified applications, TCP / UDP ratio, and anomaly alerts |
| **Service Chips** | One-click filter chips for every classified service (Google, YouTube, Netflix, …) |
| **Search & Filters** | Full-text search across IPs, ports, SNI, DNS, and payload with protocol tabs: `All` · `TLS` · `HTTP` · `DNS` · `TCP` · `UDP` · `Anomalous` |
| **Packet Table** | Color-coded protocol tags, millisecond timestamps, and source / destination addressing |
| **Deep Inspector Drawer** | Expandable tree dissecting L2 → L3 → L4 → L7 for each packet |
| **Hex / ASCII Viewer** | 16-byte hex grouping, address offsets, and one-click copy to clipboard |
| **PCAP Drag & Drop** | Drop any `.pcap` file into the browser to parse and inspect in real time |
| **Export** | Download filtered datasets as **JSON** or **CSV** |

---

## 🧪 Generating Synthetic Test Captures

```bash
python deep_packet_inspection-main/generate_test_pcap.py
```

The script produces `test_dpi.pcap` (77 packets) containing:

- **16 TLS connections** with SNI — `www.google.com`, `www.youtube.com`, `www.facebook.com`, `www.instagram.com`, `twitter.com`, `www.amazon.com`, `www.netflix.com`, `github.com`, `discord.com`, `zoom.us`, `web.telegram.org`, `www.tiktok.com`, `open.spotify.com`, `www.cloudflare.com`, `www.microsoft.com`, `www.apple.com`
- **HTTP connections** — Plaintext HTTP/1.1 requests to `example.com` and `httpbin.org`
- **DNS queries** — Standard UDP port-53 queries for major domains
- **Anomalous traffic** — 5 SYN flood packets from blocked IP `192.168.1.50`

---

## 🏗 Architecture

```
deep_packet_inspection-main/
│
├── launch.bat                          # Windows one-click launcher (CLI & Web)
├── launch.ps1                          # PowerShell launcher
├── README.md
│
├── deep_packet_inspection-main/        # Java DPI Engine
│   ├── generate_test_pcap.py           # Synthetic multi-protocol PCAP generator
│   ├── test_dpi.pcap                   # Default 77-packet test capture
│   └── src/main/java/com/packetanalyzer/
│       ├── Main.java                   # CLI entry point & DPI statistics
│       ├── PacketParser.java           # L2–L4 parsing + L7 SNI / HTTP / DNS
│       ├── ParsedPacket.java           # Packet data model with DPI fields
│       ├── PcapReader.java             # Low-level binary PCAP stream reader
│       ├── PcapGlobalHeader.java       # PCAP global header struct
│       ├── PcapPacketHeader.java       # PCAP packet header struct
│       └── RawPacket.java              # Raw byte wrapper
│
└── web/                                # Web Studio (React 19 + Vite 8 + TypeScript)
    ├── package.json
    ├── vite.config.ts                  # Dev server on port 5174
    └── src/
        ├── App.tsx                     # Main dashboard component
        ├── App.css                     # Obsidian / Cyber dark theme
        ├── index.css                   # Design tokens & glassmorphism
        ├── utils/pcapParser.ts         # Browser-side binary PCAP parser
        └── data/samplePcap.json        # Pre-parsed default capture
```

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

---

## 📄 License

This project is released under the **MIT License**. See [LICENSE](LICENSE) for details.

---

<div align="center">
  <sub>Built with ☕ Java, ⚛ React, and 🔍 curiosity.</sub>
</div>
