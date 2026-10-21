package com.inspectra;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

public class PacketParser {

    public static final int ETHERTYPE_IPV4 = 0x0800;
    public static final int ETHERTYPE_IPV6 = 0x86DD;
    public static final int ETHERTYPE_ARP = 0x0806;

    public static final int PROTO_ICMP = 1;
    public static final int PROTO_TCP = 6;
    public static final int PROTO_UDP = 17;

    public static final int TCP_FIN = 0x01;
    public static final int TCP_SYN = 0x02;
    public static final int TCP_RST = 0x04;
    public static final int TCP_PSH = 0x08;
    public static final int TCP_ACK = 0x10;
    public static final int TCP_URG = 0x20;

    public static boolean parse(RawPacket raw, ParsedPacket parsed) {
        parsed.timestampSec = raw.header.tsSec;
        parsed.timestampUsec = raw.header.tsUsec;
        
        byte[] data = raw.data;
        int len = data.length;
        
        // Use an array of size 1 to simulate a reference parameter for offset
        int[] offset = {0};
        
        if (!parseEthernet(data, len, parsed, offset)) {
            return false;
        }
        
        if (parsed.etherType == ETHERTYPE_IPV4) {
            if (!parseIPv4(data, len, parsed, offset)) {
                return false;
            }
            
            if (parsed.protocol == PROTO_TCP) {
                if (!parseTCP(data, len, parsed, offset)) {
                    return false;
                }
            } else if (parsed.protocol == PROTO_UDP) {
                if (!parseUDP(data, len, parsed, offset)) {
                    return false;
                }
            }
        }
        
        if (offset[0] < len) {
            parsed.payloadLength = len - offset[0];
            parsed.payloadData = new byte[parsed.payloadLength];
            System.arraycopy(data, offset[0], parsed.payloadData, 0, parsed.payloadLength);

            // Deep Packet Inspection (DPI)
            inspectPayload(parsed);
        } else {
            parsed.payloadLength = 0;
            parsed.payloadData = null;
        }
        
        return true;
    }

    private static void inspectPayload(ParsedPacket parsed) {
        if (parsed.payloadData == null || parsed.payloadLength == 0) return;
        
        // 1. Check TLS Client Hello SNI (TCP 443 / TLS)
        if (parsed.hasTcp) {
            String sni = extractTlsSni(parsed.payloadData, parsed.payloadLength);
            if (sni != null) {
                parsed.sni = sni;
                parsed.appType = identifyApplication(sni);
                return;
            }
            
            // 2. Check HTTP Host
            String httpHost = extractHttpHost(parsed.payloadData, parsed.payloadLength);
            if (httpHost != null) {
                parsed.httpHost = httpHost;
                parsed.appType = identifyApplication(httpHost);
                return;
            }
        }
        
        // 3. Check DNS Query (UDP port 53)
        if (parsed.hasUdp && (parsed.destPort == 53 || parsed.srcPort == 53)) {
            String dns = extractDnsQuery(parsed.payloadData, parsed.payloadLength);
            if (dns != null) {
                parsed.dnsQuery = dns;
                parsed.appType = "DNS (" + identifyApplication(dns) + ")";
                return;
            }
        }
    }

    public static String extractTlsSni(byte[] payload, int length) {
        if (length < 9) return null;
        if ((payload[0] & 0xFF) != 0x16) return null; // 0x16 = Handshake
        
        int version = ((payload[1] & 0xFF) << 8) | (payload[2] & 0xFF);
        if (version < 0x0300 || version > 0x0304) return null;
        if ((payload[5] & 0xFF) != 0x01) return null; // 0x01 = Client Hello
        
        int offset = 9; // 5 bytes record header + 4 bytes handshake header
        offset += 2;    // client version
        offset += 32;   // random
        
        if (offset >= length) return null;
        int sessionIdLen = payload[offset] & 0xFF;
        offset += 1 + sessionIdLen;
        
        if (offset + 2 > length) return null;
        int cipherSuitesLen = ((payload[offset] & 0xFF) << 8) | (payload[offset + 1] & 0xFF);
        offset += 2 + cipherSuitesLen;
        
        if (offset >= length) return null;
        int compLen = payload[offset] & 0xFF;
        offset += 1 + compLen;
        
        if (offset + 2 > length) return null;
        int extTotalLen = ((payload[offset] & 0xFF) << 8) | (payload[offset + 1] & 0xFF);
        offset += 2;
        
        int extEnd = Math.min(length, offset + extTotalLen);
        while (offset + 4 <= extEnd) {
            int extType = ((payload[offset] & 0xFF) << 8) | (payload[offset + 1] & 0xFF);
            int extLen = ((payload[offset + 2] & 0xFF) << 8) | (payload[offset + 3] & 0xFF);
            offset += 4;
            
            if (offset + extLen > extEnd) break;
            
            if (extType == 0x0000) { // SNI Extension
                if (extLen < 5) break;
                int sniListLen = ((payload[offset] & 0xFF) << 8) | (payload[offset + 1] & 0xFF);
                if (sniListLen < 3) break;
                int sniType = payload[offset + 2] & 0xFF;
                int sniLen = ((payload[offset + 3] & 0xFF) << 8) | (payload[offset + 4] & 0xFF);
                
                if (sniType == 0 && offset + 5 + sniLen <= extEnd) {
                    return new String(payload, offset + 5, sniLen, java.nio.charset.StandardCharsets.US_ASCII);
                }
            }
            offset += extLen;
        }
        return null;
    }

    public static String extractHttpHost(byte[] payload, int length) {
        if (length < 10) return null;
        String text = new String(payload, 0, Math.min(length, 1024), java.nio.charset.StandardCharsets.ISO_8859_1);
        if (!text.startsWith("GET ") && !text.startsWith("POST ") && 
            !text.startsWith("HEAD ") && !text.startsWith("PUT ") && 
            !text.startsWith("DELETE ") && !text.startsWith("OPTIONS ")) {
            return null;
        }
        int hostIdx = text.indexOf("Host:");
        if (hostIdx == -1) hostIdx = text.indexOf("host:");
        if (hostIdx != -1) {
            int start = hostIdx + 5;
            while (start < text.length() && (text.charAt(start) == ' ' || text.charAt(start) == '\t')) {
                start++;
            }
            int end = start;
            while (end < text.length() && text.charAt(end) != '\r' && text.charAt(end) != '\n') {
                end++;
            }
            if (end > start) {
                String host = text.substring(start, end).trim();
                int colon = host.indexOf(':');
                if (colon != -1) host = host.substring(0, colon);
                return host;
            }
        }
        return null;
    }

    public static String extractDnsQuery(byte[] payload, int length) {
        if (length < 12) return null;
        int qdCount = ((payload[4] & 0xFF) << 8) | (payload[5] & 0xFF);
        if (qdCount < 1) return null;
        
        int offset = 12;
        StringBuilder domain = new StringBuilder();
        while (offset < length) {
            int labelLen = payload[offset] & 0xFF;
            if (labelLen == 0) break;
            if (labelLen > 63) break;
            offset++;
            if (offset + labelLen > length) break;
            if (domain.length() > 0) domain.append(".");
            domain.append(new String(payload, offset, labelLen, java.nio.charset.StandardCharsets.US_ASCII));
            offset += labelLen;
        }
        return domain.length() > 0 ? domain.toString() : null;
    }

    public static String identifyApplication(String domainOrHost) {
        if (domainOrHost == null) return "Unknown";
        String d = domainOrHost.toLowerCase();
        if (d.contains("google")) return "Google";
        if (d.contains("youtube")) return "YouTube";
        if (d.contains("facebook")) return "Facebook";
        if (d.contains("instagram")) return "Instagram";
        if (d.contains("twitter") || d.contains("x.com")) return "Twitter / X";
        if (d.contains("netflix")) return "Netflix";
        if (d.contains("amazon")) return "Amazon";
        if (d.contains("microsoft")) return "Microsoft";
        if (d.contains("apple")) return "Apple";
        if (d.contains("whatsapp")) return "WhatsApp";
        if (d.contains("telegram")) return "Telegram";
        if (d.contains("tiktok")) return "TikTok";
        if (d.contains("spotify")) return "Spotify";
        if (d.contains("zoom")) return "Zoom";
        if (d.contains("discord")) return "Discord";
        if (d.contains("github")) return "GitHub";
        if (d.contains("cloudflare")) return "Cloudflare";
        if (d.contains("httpbin")) return "HTTPBin";
        if (d.contains("example")) return "Example Domain";
        return domainOrHost;
    }

    private static boolean parseEthernet(byte[] data, int len, ParsedPacket parsed, int[] offset) {
        if (len < 14) return false;
        
        parsed.destMac = macToString(data, 0);
        parsed.srcMac = macToString(data, 6);
        
        // EtherType is big endian
        ByteBuffer bb = ByteBuffer.wrap(data, 12, 2);
        bb.order(ByteOrder.BIG_ENDIAN);
        parsed.etherType = bb.getShort() & 0xFFFF;
        
        offset[0] = 14;
        return true;
    }

    private static boolean parseIPv4(byte[] data, int len, ParsedPacket parsed, int[] offset) {
        if (len < offset[0] + 20) return false;
        
        int start = offset[0];
        int versionIhl = data[start] & 0xFF;
        parsed.ipVersion = (versionIhl >> 4) & 0x0F;
        int ihl = versionIhl & 0x0F;
        
        if (parsed.ipVersion != 4) return false;
        
        int ipHeaderLen = ihl * 4;
        if (ipHeaderLen < 20 || len < start + ipHeaderLen) return false;
        
        parsed.ttl = data[start + 8] & 0xFF;
        parsed.protocol = data[start + 9] & 0xFF;
        
        parsed.srcIp = ipToString(data, start + 12);
        parsed.destIp = ipToString(data, start + 16);
        
        parsed.hasIp = true;
        offset[0] += ipHeaderLen;
        return true;
    }

    private static boolean parseTCP(byte[] data, int len, ParsedPacket parsed, int[] offset) {
        if (len < offset[0] + 20) return false;
        
        int start = offset[0];
        ByteBuffer bb = ByteBuffer.wrap(data, start, len - start);
        bb.order(ByteOrder.BIG_ENDIAN); // Network byte order
        
        parsed.srcPort = bb.getShort() & 0xFFFF;
        parsed.destPort = bb.getShort() & 0xFFFF;
        parsed.seqNumber = bb.getInt() & 0xFFFFFFFFL;
        parsed.ackNumber = bb.getInt() & 0xFFFFFFFFL;
        
        int dataOffset = (data[start + 12] >> 4) & 0x0F;
        int tcpHeaderLen = dataOffset * 4;
        
        parsed.tcpFlags = data[start + 13] & 0xFF;
        
        if (tcpHeaderLen < 20 || len < start + tcpHeaderLen) return false;
        
        parsed.hasTcp = true;
        offset[0] += tcpHeaderLen;
        return true;
    }

    private static boolean parseUDP(byte[] data, int len, ParsedPacket parsed, int[] offset) {
        if (len < offset[0] + 8) return false;
        
        int start = offset[0];
        ByteBuffer bb = ByteBuffer.wrap(data, start, 8);
        bb.order(ByteOrder.BIG_ENDIAN);
        
        parsed.srcPort = bb.getShort() & 0xFFFF;
        parsed.destPort = bb.getShort() & 0xFFFF;
        
        parsed.hasUdp = true;
        offset[0] += 8;
        return true;
    }

    public static String macToString(byte[] mac, int offset) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 6; i++) {
            if (i > 0) sb.append(":");
            sb.append(String.format("%02x", mac[offset + i] & 0xFF));
        }
        return sb.toString();
    }

    public static String ipToString(byte[] ip, int offset) {
        return (ip[offset] & 0xFF) + "." +
               (ip[offset + 1] & 0xFF) + "." +
               (ip[offset + 2] & 0xFF) + "." +
               (ip[offset + 3] & 0xFF);
    }

    public static String protocolToString(int protocol) {
        switch (protocol) {
            case PROTO_ICMP: return "ICMP";
            case PROTO_TCP: return "TCP";
            case PROTO_UDP: return "UDP";
            default: return "Unknown(" + protocol + ")";
        }
    }

    public static String tcpFlagsToString(int flags) {
        StringBuilder result = new StringBuilder();
        if ((flags & TCP_SYN) != 0) result.append("SYN ");
        if ((flags & TCP_ACK) != 0) result.append("ACK ");
        if ((flags & TCP_FIN) != 0) result.append("FIN ");
        if ((flags & TCP_RST) != 0) result.append("RST ");
        if ((flags & TCP_PSH) != 0) result.append("PSH ");
        if ((flags & TCP_URG) != 0) result.append("URG ");
        
        String res = result.toString().trim();
        return res.isEmpty() ? "none" : res;
    }
}
