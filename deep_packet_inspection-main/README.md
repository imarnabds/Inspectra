# DeepPacket.AI — Deep Packet Inspection (DPI) & Network Protocol Studio

A high-performance Network Packet Analyzer and Deep Packet Inspection (DPI) suite designed to parse raw PCAP captures, decode multi-layer protocol headers, extract Layer-7 application metadata (TLS SNI, HTTP Host, DNS queries), and classify network traffic with security anomaly detection.

The project features both a **Java Core Inspection Engine** and a **Modern Interactive Web Studio** running at **`http://localhost:5174/`**.

---

## 🌟 Key Capabilities

- **Multi-Layer Protocol Dissection**:
  - **Layer 2 (Data Link)**: Ethernet II framing, Source/Destination MAC addresses, EtherType (`0x0800` IPv4, `0x86dd` IPv6, `0x0806` ARP).
  - **Layer 3 (Network)**: IPv4 header validation, TTL hop limits, Protocol classification, Source & Destination IP mapping.
  - **Layer 4 (Transport)**: 
    - **TCP**: Source/Destination ports, Sequence & Acknowledgement numbers, Flag decoding (`SYN`, `ACK`, `PSH`, `FIN`, `RST`, `URG`).
    - **UDP**: Source/Destination ports, datagram length validation.
  - **Layer 7 (Deep Packet Inspection - DPI)**:
    - **TLS Client Hello SNI**: Decodes TLS record headers (v1.0–v1.3), walks extension blocks, and extracts Server Name Indication (SNI) hostnames.
    - **HTTP Host Dissection**: Scans HTTP methods (`GET`, `POST`, `HEAD`, etc.) and extracts `Host:` headers.
    - **DNS Query Extraction**: Decodes UDP port 53 DNS question sections and extracts domain queries.
    - **Service Classification**: Maps hostnames and domains to 16+ known services (Google, YouTube, Facebook, Twitter/X, Netflix, Amazon, GitHub, Discord, Telegram, TikTok, Spotify, Zoom, Cloudflare, Microsoft, Apple, HTTPBin).
- **Security & Anomaly Detection**: Highlights suspicious traffic, anomalous source addresses, and simulated SYN floods (e.g. `192.168.1.50`).
- **Interactive Web Studio**: Real-time packet stream table, expandable protocol layer tree, synchronized Hex/ASCII byte dump viewer, drag-and-drop PCAP parser, and JSON/CSV export.

---

## 🚀 Quick Launch Guide

> [!IMPORTANT]
> If running from Windows Command Prompt (`cmd.exe`), remember to switch to drive **`E:`** first:
> ```cmd
> E:
> cd \Projects\deep_packet_inspection-main
> ```

### Option 1: Launch the Web Studio Dashboard (Recommended)
Run the automated launcher with the `web` argument:
```cmd
launch.bat web
```
Then open your browser to **[http://localhost:5174/](http://localhost:5174/)**.

*(Or via npm directly inside the `web` folder: `cd web && npm run dev`)*

---

### Option 2: Run the Java CLI Analyzer
Execute the batch script without arguments to analyze the default PCAP capture:
```cmd
launch.bat
```
To limit the output to the first $N$ packets (e.g., first 10 packets):
```cmd
launch.bat 10
```

---

### Option 3: PowerShell Launcher
```powershell
.\launch.ps1
```
Or with custom packet count or capture path:
```powershell
.\launch.ps1 -PcapFile "deep_packet_inspection-main\test_dpi.pcap" -MaxPackets 15
```

---

### Option 4: Direct Java Commands
Compile and run the Java engine directly:
```cmd
cd deep_packet_inspection-main
javac -d src/main/java src/main/java/com/packetanalyzer/*.java
java -cp src/main/java com.packetanalyzer.Main test_dpi.pcap
```

---

## 🖥️ Web Studio Interface Features

| Feature | Description |
| :--- | :--- |
| **KPI Metrics Bar** | Displays total captured packets, inspected payload volume, identified application count, TCP/UDP split ratio, and security anomaly alerts. |
| **Service Classification Chips** | One-click filter chips for all identified applications (Google, YouTube, Facebook, Twitter, Amazon, Netflix, etc.). |
| **Search & Filter Toolbar** | Full-text search across IPs, ports, SNI hostnames, DNS domains, and payload text, with protocol filter tabs (`All`, `TLS`, `HTTP`, `DNS`, `TCP`, `UDP`, `Anomalous`). |
| **Wireshark-Grade Packet Table** | Color-coded protocol tags, millisecond timestamp tracking, and source/dest addressing. |
| **Deep Packet Inspector Drawer** | Expandable card tree dissecting Layer 2 (Ethernet), Layer 3 (IPv4), Layer 4 (TCP/UDP), and Layer 7 (DPI). |
| **Synchronized Hex / ASCII Viewer** | Formatted byte stream with 16-byte hex grouping, address offsets, and one-click copy. |
| **Drag & Drop PCAP Uploader** | Drop any custom `.pcap` capture file directly into the browser to parse and dissect in real-time. |
| **Data Export** | Export filtered packet datasets to **JSON** or **CSV** formats. |

---

## 🛠️ Generating Synthetic Test Captures

The repository includes a Python test traffic generator:
```cmd
python generate_test_pcap.py
```
This synthesizes [test_dpi.pcap](file:///e:/Projects/deep_packet_inspection-main/deep_packet_inspection-main/test_dpi.pcap) with:
- **16 TLS Connections with SNI**: `www.google.com`, `www.youtube.com`, `www.facebook.com`, `www.instagram.com`, `twitter.com`, `www.amazon.com`, `www.netflix.com`, `github.com`, `discord.com`, `zoom.us`, `web.telegram.org`, `www.tiktok.com`, `open.spotify.com`, `www.cloudflare.com`, `www.microsoft.com`, `www.apple.com`
- **HTTP Connections**: Plaintext HTTP/1.1 requests (`example.com`, `httpbin.org`)
- **DNS Queries (UDP 53)**: Standard queries for major domains
- **Anomalous Traffic**: 5 SYN flood packets from blocked IP `192.168.1.50`

---

## 📁 Repository Structure

```
deep_packet_inspection-main/
├── launch.bat                     # Windows 1-click launcher (CLI & Web Dashboard)
├── launch.ps1                     # PowerShell launch script
├── README.md                      # Complete documentation & guide
├── deep_packet_inspection-main/
│   ├── generate_test_pcap.py      # Multi-protocol synthetic PCAP generator
│   ├── test_dpi.pcap              # Default 77-packet test capture
│   ├── launch.bat                 # Local directory launcher
│   └── src/main/java/com/packetanalyzer/
│       ├── Main.java              # Java CLI entry point & DPI statistics
│       ├── PacketParser.java      # L2-L4 parsing & L7 SNI/HTTP/DNS dissection
│       ├── ParsedPacket.java      # Packet data model with DPI fields
│       ├── PcapReader.java        # Low-level binary PCAP stream reader
│       ├── PcapGlobalHeader.java  # PCAP global header structure
│       ├── PcapPacketHeader.java  # PCAP packet header structure
│       └── RawPacket.java         # Raw byte wrapper
└── web/                           # DeepPacket.AI Web Studio (React + Vite + TypeScript)
    ├── package.json               # Frontend dependencies & scripts
    ├── vite.config.ts             # Vite server config (Port 5174)
    ├── src/
    │   ├── App.tsx                # Main dashboard component
    │   ├── App.css                # Obsidian/Cyber dark theme styling
    │   ├── index.css              # Design tokens, typography & glassmorphism
    │   ├── utils/pcapParser.ts    # Browser-side binary PCAP parser
    │   └── data/samplePcap.json   # Pre-parsed default capture data
    └── public/
        └── samplePcap.json        # Public dataset
```

---

## 🔧 Troubleshooting

- **`'launch.bat' is not recognized as an internal or external command`**:
  Ensure your terminal is located on drive `E:` inside the project directory:
  ```cmd
  E:
  cd \Projects\deep_packet_inspection-main
  ```
- **Port Conflict (`5173` in use)**:
  The Web Studio is preconfigured to use port **`5174`** (`http://localhost:5174/`) to avoid collisions with any existing dev servers on port 5173.
- **PowerShell Script Execution Policy**:
  If PowerShell blocks `.ps1` execution, run `launch.bat` in Command Prompt, or launch with:
  ```powershell
  powershell -ExecutionPolicy Bypass -File .\launch.ps1
  ```