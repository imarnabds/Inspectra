package com.inspectra;

import java.io.FileInputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

public class PcapReader {
    private static final long PCAP_MAGIC_NATIVE = 0xa1b2c3d4L;
    private static final long PCAP_MAGIC_SWAPPED = 0xd4c3b2a1L;
    
    private FileInputStream fis;
    private PcapGlobalHeader globalHeader;
    private boolean needsByteSwap = false;
    private ByteOrder fileByteOrder = ByteOrder.nativeOrder();

    public boolean open(String filename) {
        close();
        try {
            fis = new FileInputStream(filename);
            
            // Read the global header (24 bytes)
            byte[] globalHeaderBytes = new byte[24];
            if (fis.read(globalHeaderBytes) != 24) {
                System.err.println("Error: Could not read PCAP global header");
                close();
                return false;
            }
            
            ByteBuffer bb = ByteBuffer.wrap(globalHeaderBytes);
            bb.order(ByteOrder.LITTLE_ENDIAN); // default assumption, will check magic
            
            long magic = bb.getInt() & 0xFFFFFFFFL;
            
            if (magic == PCAP_MAGIC_NATIVE || magic == PCAP_MAGIC_SWAPPED) {
                // If it's natively little endian and we got swapped, it means the file is big endian
                if (magic == PCAP_MAGIC_SWAPPED) {
                    needsByteSwap = true;
                    fileByteOrder = ByteOrder.BIG_ENDIAN;
                } else {
                    needsByteSwap = false;
                    fileByteOrder = ByteOrder.LITTLE_ENDIAN;
                }
            } else {
                // Try Big Endian assumption
                bb.order(ByteOrder.BIG_ENDIAN);
                bb.position(0);
                magic = bb.getInt() & 0xFFFFFFFFL;
                if (magic == PCAP_MAGIC_NATIVE) {
                    fileByteOrder = ByteOrder.BIG_ENDIAN;
                } else if (magic == PCAP_MAGIC_SWAPPED) {
                    fileByteOrder = ByteOrder.LITTLE_ENDIAN;
                } else {
                    System.err.printf("Error: Invalid PCAP magic number: 0x%x\n", magic);
                    close();
                    return false;
                }
            }
            
            bb.order(fileByteOrder);
            bb.position(0); // reset after magic check
            
            globalHeader = new PcapGlobalHeader();
            globalHeader.magicNumber = bb.getInt() & 0xFFFFFFFFL;
            globalHeader.versionMajor = bb.getShort() & 0xFFFF;
            globalHeader.versionMinor = bb.getShort() & 0xFFFF;
            globalHeader.thiszone = bb.getInt();
            globalHeader.sigfigs = bb.getInt() & 0xFFFFFFFFL;
            globalHeader.snaplen = bb.getInt() & 0xFFFFFFFFL;
            globalHeader.network = bb.getInt() & 0xFFFFFFFFL;
            
            System.out.println("Inspectra PCAP Reader: Opened file: " + filename);
            System.out.println("  Version: " + globalHeader.versionMajor + "." + globalHeader.versionMinor);
            System.out.println("  Snaplen: " + globalHeader.snaplen + " bytes");
            System.out.println("  Link type: " + globalHeader.network + (globalHeader.network == 1 ? " (Ethernet)" : ""));
            
            return true;
        } catch (IOException e) {
            System.err.println("Error: Could not open file: " + filename);
            return false;
        }
    }

    public void close() {
        if (fis != null) {
            try {
                fis.close();
            } catch (IOException e) {
                // ignore
            }
            fis = null;
        }
    }

    public boolean readNextPacket(RawPacket packet) {
        if (fis == null) {
            return false;
        }
        
        try {
            // Read the packet header (16 bytes)
            byte[] headerBytes = new byte[16];
            int read = fis.read(headerBytes);
            if (read == -1) return false; // EOF
            if (read != 16) return false;
            
            ByteBuffer bb = ByteBuffer.wrap(headerBytes);
            bb.order(fileByteOrder);
            
            packet.header.tsSec = bb.getInt() & 0xFFFFFFFFL;
            packet.header.tsUsec = bb.getInt() & 0xFFFFFFFFL;
            packet.header.inclLen = bb.getInt() & 0xFFFFFFFFL;
            packet.header.origLen = bb.getInt() & 0xFFFFFFFFL;
            
            if (packet.header.inclLen > globalHeader.snaplen || packet.header.inclLen > 65535) {
                System.err.println("Error: Invalid packet length: " + packet.header.inclLen);
                return false;
            }
            
            // Read packet data
            packet.data = new byte[(int)packet.header.inclLen];
            int dataRead = fis.read(packet.data);
            if (dataRead != packet.header.inclLen) {
                System.err.println("Error: Could not read full packet data");
                return false;
            }
            
            return true;
        } catch (IOException e) {
            return false;
        }
    }
}
