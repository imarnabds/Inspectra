package com.packetanalyzer;

import java.text.SimpleDateFormat;
import java.util.Date;

public class Main {
    
    private static void printPacketSummary(ParsedPacket pkt, int packetNum) {
        // Format timestamp
        Date date = new Date(pkt.timestampSec * 1000L);
        SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
        
        System.out.println("\n========== Packet #" + packetNum + " ==========");
        System.out.printf("Time: %s.%06d\n", sdf.format(date), pkt.timestampUsec);
        
        // Ethernet layer
        System.out.println("\n[Ethernet]");
        System.out.println("  Source MAC:      " + pkt.srcMac);
        System.out.println("  Destination MAC: " + pkt.destMac);
        System.out.printf("  EtherType:       0x%04x", pkt.etherType);
        
        if (pkt.etherType == PacketParser.ETHERTYPE_IPV4) {
            System.out.print(" (IPv4)");
        } else if (pkt.etherType == PacketParser.ETHERTYPE_IPV6) {
            System.out.print(" (IPv6)");
        } else if (pkt.etherType == PacketParser.ETHERTYPE_ARP) {
            System.out.print(" (ARP)");
        }
        System.out.println();
        
        // IP layer
        if (pkt.hasIp) {
            System.out.println("\n[IPv" + pkt.ipVersion + "]");
            System.out.println("  Source IP:      " + pkt.srcIp);
            System.out.println("  Destination IP: " + pkt.destIp);
            System.out.println("  Protocol:       " + PacketParser.protocolToString(pkt.protocol));
            System.out.println("  TTL:            " + pkt.ttl);
        }
        
        // TCP layer
        if (pkt.hasTcp) {
            System.out.println("\n[TCP]");
            System.out.println("  Source Port:      " + pkt.srcPort);
            System.out.println("  Destination Port: " + pkt.destPort);
            System.out.println("  Sequence Number:  " + pkt.seqNumber);
            System.out.println("  Ack Number:       " + pkt.ackNumber);
            System.out.println("  Flags:            " + PacketParser.tcpFlagsToString(pkt.tcpFlags));
        }
        
        // UDP layer
        if (pkt.hasUdp) {
            System.out.println("\n[UDP]");
            System.out.println("  Source Port:      " + pkt.srcPort);
            System.out.println("  Destination Port: " + pkt.destPort);
        }

        // Deep Packet Inspection (DPI) layer
        if (pkt.appType != null || pkt.sni != null || pkt.httpHost != null || pkt.dnsQuery != null) {
            System.out.println("\n[Deep Packet Inspection (DPI)]");
            if (pkt.appType != null) {
                System.out.println("  Identified App:   " + pkt.appType);
            }
            if (pkt.sni != null) {
                System.out.println("  TLS SNI:          " + pkt.sni);
            }
            if (pkt.httpHost != null) {
                System.out.println("  HTTP Host:        " + pkt.httpHost);
            }
            if (pkt.dnsQuery != null) {
                System.out.println("  DNS Query Domain: " + pkt.dnsQuery);
            }
        }
        
        // Payload info
        if (pkt.payloadLength > 0 && pkt.payloadData != null) {
            System.out.println("\n[Payload]");
            System.out.println("  Length: " + pkt.payloadLength + " bytes");
            
            System.out.print("  Preview: ");
            int previewLen = Math.min(pkt.payloadLength, 32);
            for (int i = 0; i < previewLen; i++) {
                System.out.printf("%02x ", pkt.payloadData[i] & 0xFF);
            }
            if (pkt.payloadLength > 32) {
                System.out.print("...");
            }
            System.out.println();
        }
    }
    
    private static void printUsage(String programName) {
        System.out.println("Usage: java " + programName + " <pcap_file> [max_packets]");
        System.out.println("\nArguments:");
        System.out.println("  pcap_file   - Path to a .pcap file captured by Wireshark");
        System.out.println("  max_packets - (Optional) Maximum number of packets to display");
        System.out.println("\nExample:");
        System.out.println("  java " + programName + " capture.pcap");
        System.out.println("  java " + programName + " capture.pcap 10");
    }

    public static void main(String[] args) {
        System.out.println("====================================");
        System.out.println("  Deep Packet Inspection Analyzer v1.0");
        System.out.println("====================================\n");
        
        if (args.length < 1) {
            printUsage("com.packetanalyzer.Main");
            return;
        }
        
        String filename = args[0];
        int maxPackets = -1;
        
        if (args.length >= 2) {
            try {
                maxPackets = Integer.parseInt(args[1]);
            } catch (NumberFormatException e) {
                // ignore
            }
        }
        
        PcapReader reader = new PcapReader();
        if (!reader.open(filename)) {
            return;
        }
        
        System.out.println("\n--- Reading packets ---");
        
        RawPacket rawPacket = new RawPacket();
        ParsedPacket parsedPacket = new ParsedPacket();
        int packetCount = 0;
        int parseErrors = 0;
        int tcpCount = 0;
        int udpCount = 0;
        long totalPayloadBytes = 0;
        java.util.Map<String, Integer> appStats = new java.util.LinkedHashMap<>();
        
        while (reader.readNextPacket(rawPacket)) {
            packetCount++;
            
            if (PacketParser.parse(rawPacket, parsedPacket)) {
                printPacketSummary(parsedPacket, packetCount);
                
                if (parsedPacket.hasTcp) tcpCount++;
                if (parsedPacket.hasUdp) udpCount++;
                totalPayloadBytes += parsedPacket.payloadLength;
                
                if (parsedPacket.appType != null) {
                    appStats.put(parsedPacket.appType, appStats.getOrDefault(parsedPacket.appType, 0) + 1);
                }
            } else {
                System.err.println("Warning: Failed to parse packet #" + packetCount);
                parseErrors++;
            }
            
            if (maxPackets > 0 && packetCount >= maxPackets) {
                System.out.println("\n(Stopped after " + maxPackets + " packets)");
                break;
            }
            
            // Re-instantiate for next packet to avoid carrying over state by mistake
            rawPacket = new RawPacket();
            parsedPacket = new ParsedPacket();
        }
        
        System.out.println("\n====================================");
        System.out.println("Summary & Deep Packet Inspection Statistics:");
        System.out.println("  Total packets read:     " + packetCount);
        System.out.println("  TCP Packets:            " + tcpCount);
        System.out.println("  UDP Packets:            " + udpCount);
        System.out.println("  Payload bytes inspected:" + totalPayloadBytes + " bytes");
        System.out.println("  Parse errors:           " + parseErrors);
        
        if (!appStats.isEmpty()) {
            System.out.println("\n  Identified Applications & Protocols:");
            for (java.util.Map.Entry<String, Integer> entry : appStats.entrySet()) {
                System.out.printf("    - %-22s : %d packet(s)\n", entry.getKey(), entry.getValue());
            }
        }
        System.out.println("====================================");
        
        reader.close();
    }
}
