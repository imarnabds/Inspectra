package com.packetanalyzer;

public class PcapPacketHeader {
    public long tsSec;         // Timestamp seconds
    public long tsUsec;        // Timestamp microseconds
    public long inclLen;       // Number of bytes saved in file
    public long origLen;       // Actual length of packet
}
