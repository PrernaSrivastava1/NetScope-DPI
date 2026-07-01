package com.packetanalyzer.parser;

import com.packetanalyzer.model.RawPacket;
import com.packetanalyzer.utils.ByteUtils;
import java.io.*;

public class PcapReader implements AutoCloseable {
    private InputStream inputStream;
    private final byte[] globalHeaderBytes = new byte[24];
    private boolean needsByteSwap = false;
    private long snaplen;
    private long network;

    public boolean open(String filename) {
        try {
            close();
            inputStream = new BufferedInputStream(new FileInputStream(filename));
            int read = inputStream.read(globalHeaderBytes);
            if (read < 24) {
                System.err.println("Error: Could not read PCAP global header");
                close();
                return false;
            }

            long magicNumber = ByteUtils.readUint32LE(globalHeaderBytes, 0);
            if (magicNumber == 0xa1b2c3d4L) {
                needsByteSwap = false;
            } else if (magicNumber == 0xd4c3b2a1L) {
                needsByteSwap = true;
            } else {
                System.err.println("Error: Invalid PCAP magic number: 0x" + Long.toHexString(magicNumber));
                close();
                return false;
            }

            // Parse version, snaplen, and network
            int versionMajor = readUint16(globalHeaderBytes, 4);
            int versionMinor = readUint16(globalHeaderBytes, 6);
            snaplen = readUint32(globalHeaderBytes, 16);
            network = readUint32(globalHeaderBytes, 20);

            System.out.println("Opened PCAP file: " + filename);
            System.out.println("  Version: " + versionMajor + "." + versionMinor);
            System.out.println("  Snaplen: " + snaplen + " bytes");
            System.out.println("  Link type: " + network + (network == 1 ? " (Ethernet)" : ""));

            return true;
        } catch (IOException e) {
            System.err.println("Error: Could not open file: " + filename);
            return false;
        }
    }

    public byte[] getGlobalHeaderBytes() {
        return globalHeaderBytes;
    }

    public boolean readNextPacket(RawPacket[] packetRef) {
        if (inputStream == null) return false;
        try {
            byte[] headerBytes = new byte[16];
            int read = readFully(headerBytes);
            if (read < 16) {
                return false; // EOF
            }

            long tsSec = readUint32(headerBytes, 0);
            long tsUsec = readUint32(headerBytes, 4);
            long inclLen = readUint32(headerBytes, 8);
            long origLen = readUint32(headerBytes, 12);

            if (inclLen > snaplen || inclLen > 65535) {
                System.err.println("Error: Invalid packet length: " + inclLen);
                return false;
            }

            byte[] data = new byte[(int) inclLen];
            read = readFully(data);
            if (read < inclLen) {
                System.err.println("Error: Could not read packet data");
                return false;
            }

            RawPacket.Header header = new RawPacket.Header((int) tsSec, (int) tsUsec, (int) inclLen, (int) origLen);
            packetRef[0] = new RawPacket(header, data);
            return true;
        } catch (IOException e) {
            return false;
        }
    }

    private int readFully(byte[] buffer) throws IOException {
        int totalRead = 0;
        while (totalRead < buffer.length) {
            int read = inputStream.read(buffer, totalRead, buffer.length - totalRead);
            if (read == -1) break;
            totalRead += read;
        }
        return totalRead;
    }

    @Override
    public void close() {
        if (inputStream != null) {
            try {
                inputStream.close();
            } catch (IOException ignored) {}
            inputStream = null;
        }
        needsByteSwap = false;
    }

    private int readUint16(byte[] data, int offset) {
        if (needsByteSwap) {
            return ByteUtils.readUint16BE(data, offset);
        } else {
            return ByteUtils.readUint16LE(data, offset);
        }
    }

    private long readUint32(byte[] data, int offset) {
        if (needsByteSwap) {
            return ByteUtils.readUint32BE(data, offset);
        } else {
            return ByteUtils.readUint32LE(data, offset);
        }
    }

    public boolean needsByteSwap() {
        return needsByteSwap;
    }

    public long getSnaplen() {
        return snaplen;
    }

    public long getNetwork() {
        return network;
    }
}
