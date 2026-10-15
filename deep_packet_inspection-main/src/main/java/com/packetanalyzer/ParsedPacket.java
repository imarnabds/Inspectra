package com.packetanalyzer;

public class ParsedPacket {
    // Timestamps
    public long timestampSec;
    public long timestampUsec;
    
    // Ethernet layer
    public String srcMac = "";
    public String destMac = "";
    public int etherType;
    
    // IP layer (if present)
    public boolean hasIp = false;
    public int ipVersion;
    public String srcIp = "";
    public String destIp = "";
    public int protocol;          
    public int ttl;
    
    // Transport layer (if present)
    public boolean hasTcp = false;
    public boolean hasUdp = false;
    public int srcPort;
    public int destPort;
    
    // TCP-specific
    public int tcpFlags;
    public long seqNumber;
    public long ackNumber;
    
    // Payload
    public int payloadLength;
    public byte[] payloadData = null;

    // Deep Packet Inspection (DPI) Layer
    public String appType = null;
    public String sni = null;
    public String httpHost = null;
    public String dnsQuery = null;
}
