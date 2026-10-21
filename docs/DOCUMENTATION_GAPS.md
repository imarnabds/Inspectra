# Inspectra: Documentation Gaps & Engineering Roadmap

This document outlines prioritized discrepancies between production requirements, design ambitions, and the active codebase. Distinguishing **documentation gaps** from **code defects** is vital for technical credibility in interviews, architecture reviews, and future development.

---

## 1. Documentation Gaps (Information Requiring Formalization)

| Priority | Documentation Item | Affected Components | Root Cause & Resolution |
| :---: | :--- | :--- | :--- |
| **P0** | **C++ Pipeline Build & Linking Instructions** | `deep_packet_inspection-main/src/` | While Java and Web Studio have one-click scripts (`launch.bat`, `launch.ps1`), the C++ multi-threaded engine (`dpi_mt.cpp`, `main_dpi.cpp`) lacks a standardized `CMakeLists.txt` or `Makefile`. Documenting the exact compiler flags (`g++ -std=c++17 -pthread ...` or MSVC cl) is needed. |
| **P0** | **Explicit Distinction Between Implemented Rules vs Planned ML** | Core README & Architecture Docs | Legacy architectural notes loosely referenced "Machine Learning" and "Statistical Anomaly Detection." The documentation must clearly distinguish the implemented rule-based/DPI heuristic classifier from the architected Random Forest/KS models. |
| **P1** | **Internal Binary Struct Specifications** | `PcapReader`, `FastPathProcessor` | Detail the exact byte offsets, memory alignment, and network endianness expectations for RFC 791 (IPv4), RFC 793 (TCP), and RFC 8446 (TLS 1.3) to aid new developers. |
| **P1** | **Standardized Benchmark Methodology** | Performance & Scalability | The repository lacks a published automated throughput benchmark script (measuring packets/second under synthetic load). Document a reproducible methodology using `tcpreplay` and `iperf3`. |
| **P2** | **Export Schema Specifications** | `App.tsx` (JSON & CSV exports) | Formalize the field dictionaries and JSON schemas for exported forensic datasets (`inspectra_export_*.json`) to assist SIEM/SOC integration. |

---

## 2. Codebase Engineering Gaps (Functionality Remaining to Be Implemented)

### A. Machine Learning Inference & Statistical Analysis
- **Current State**: Deterministic rule and substring matching (`identifyApplication` / `sniToAppType`) with hardcoded domain patterns.
- **Missing Code**:
  - Python training scripts for traffic classification using public benchmark datasets (e.g., CIC-IDS2017, UNSW-NB15).
  - Feature extraction module producing numerical vectors (e.g., mean packet size, standard deviation of inter-arrival times, payload byte entropy, flow byte ratio).
  - Model serialization/deserialization (e.g., ONNX runtime or lightweight C++ Random Forest inference header).
  - Kolmogorov-Smirnov (KS) distance two-sample test comparing sliding-window flow distributions against baseline distributions.

### B. Live Kernel Packet Capture
- **Current State**: Standalone offline PCAP binary stream reader.
- **Missing Code**:
  - Direct integration with OS-level capture engines such as `libpcap` (Linux/macOS), Npcap/WinPcap (Windows), or Linux `eBPF` (XDP).
  - Continuous ring-buffer capture with dropped-packet counters.

### C. Active Kernel Firewall Enforcement
- **Current State**: Filtered packets are written out to an output `.pcap` capture file in user space (`writeOutputPacket`).
- **Missing Code**:
  - Active kernel-level drop triggers via Linux `nftables`/`iptables` or macOS `pfctl`.
  - Safety controls: Fail-safe watchdog timers, automatic rule timeout rollback, and loopback/admin subnet allowlists to prevent accidental lockout.

### D. Automated Unit and Integration Test Suite
- **Current State**: Manual verification via automated launch scripts (`launch.bat`, `launch.ps1`), Python synthetic capture generation, and live browser testing.
- **Missing Code**:
  - Automated JUnit 5 / AssertJ test suite for Java (`PcapReaderTest.java`, `PacketParserTest.java`).
  - GoogleTest / Catch2 suite for C++ (`connection_tracker_test.cpp`, `rule_manager_test.cpp`).
  - Vitest / Playwright regression tests for the Web Studio interface.
