package com.inspectra;

public class RawPacket {
    public PcapPacketHeader header;
    public byte[] data;
    
    public RawPacket() {
        header = new PcapPacketHeader();
    }
}
