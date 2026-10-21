# Inspectra Web Studio

Modern, interactive Deep Packet Inspection (DPI) & Network Observability Studio built with **React 19**, **TypeScript 6**, **Vite 8**, and **Lucide Icons**.

## Features

- **Wireshark-Grade Packet Table**: Real-time traffic stream with protocol badges (TLS, HTTP, DNS, TCP, UDP, Anomalous).
- **Inspectra In-Memory Capture Database**: Fast client-side packet storage and indexing for real-time querying and filtering.
- **Deep Packet Inspector**: Interactive tree dissection covering Layer 2 (Ethernet), Layer 3 (IPv4), Layer 4 (TCP/UDP), and Layer 7 (TLS SNI, HTTP Host, DNS queries).
- **Synchronized Hex / ASCII Byte Stream**: 16-byte aligned hex view with offset markers and one-click clipboard copy.
- **Zero-Backend PCAP Ingestion**: Drag and drop any `.pcap` or `.cap` capture file directly into the browser for immediate byte-level dissection.
- **Data Export**: Export filtered packet datasets to JSON or CSV (`inspectra_export_<timestamp>`).

## Getting Started

```bash
# Install dependencies
npm install

# Start development server on port 5174
npm run dev

# Build production bundle
npm run build
```
