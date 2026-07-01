package com.packetanalyzer.utils;

public class ByteUtils {

    public static int readUint16BE(byte[] data, int offset) {
        return ((data[offset] & 0xFF) << 8) | (data[offset + 1] & 0xFF);
    }

    public static long readUint32BE(byte[] data, int offset) {
        return (((long) (data[offset] & 0xFF)) << 24) |
               (((long) (data[offset + 1] & 0xFF)) << 16) |
               (((long) (data[offset + 2] & 0xFF)) << 8) |
               ((long) (data[offset + 3] & 0xFF));
    }

    public static int readUint16LE(byte[] data, int offset) {
        return (data[offset] & 0xFF) | ((data[offset + 1] & 0xFF) << 8);
    }

    public static int readInt16LE(byte[] data, int offset) {
        return (data[offset] & 0xFF) | (data[offset + 1] << 8);
    }

    public static long readUint32LE(byte[] data, int offset) {
        return ((data[offset] & 0xFF) & 0xFFFFFFFFL) |
               (((data[offset + 1] & 0xFF) << 8) & 0xFFFFFFFFL) |
               (((data[offset + 2] & 0xFF) << 16) & 0xFFFFFFFFL) |
               (((long) (data[offset + 3] & 0xFF)) << 24);
    }

    public static int readInt32LE(byte[] data, int offset) {
        return (data[offset] & 0xFF) |
               ((data[offset + 1] & 0xFF) << 8) |
               ((data[offset + 2] & 0xFF) << 16) |
               (data[offset + 3] << 24);
    }

    public static int readUint24BE(byte[] data, int offset) {
        return ((data[offset] & 0xFF) << 16) |
               ((data[offset + 1] & 0xFF) << 8) |
               (data[offset + 2] & 0xFF);
    }

    public static int swap16(int value) {
        return ((value & 0xFF00) >> 8) | ((value & 0x00FF) << 8);
    }

    public static int swap32(int value) {
        return ((value & 0xFF000000) >>> 24) |
               ((value & 0x00FF0000) >>> 8) |
               ((value & 0x0000FF00) << 8) |
               ((value & 0x000000FF) << 24);
    }

    public static long swap32(long value) {
        return ((value & 0xFF000000L) >>> 24) |
               ((value & 0x00FF0000L) >>> 8) |
               ((value & 0x0000FF00L) << 8) |
               ((value & 0x000000FFL) << 24);
    }

    public static String macToString(byte[] mac, int offset) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 6; i++) {
            if (i > 0) sb.append(":");
            sb.append(String.format("%02x", mac[offset + i]));
        }
        return sb.toString();
    }

    public static byte[] serializePacketHeader(int tsSec, int tsUsec, int inclLen, int origLen, boolean bigEndian) {
        byte[] header = new byte[16];
        if (bigEndian) {
            header[0] = (byte) ((tsSec >> 24) & 0xFF);
            header[1] = (byte) ((tsSec >> 16) & 0xFF);
            header[2] = (byte) ((tsSec >> 8) & 0xFF);
            header[3] = (byte) (tsSec & 0xFF);

            header[4] = (byte) ((tsUsec >> 24) & 0xFF);
            header[5] = (byte) ((tsUsec >> 16) & 0xFF);
            header[6] = (byte) ((tsUsec >> 8) & 0xFF);
            header[7] = (byte) (tsUsec & 0xFF);

            header[8] = (byte) ((inclLen >> 24) & 0xFF);
            header[9] = (byte) ((inclLen >> 16) & 0xFF);
            header[10] = (byte) ((inclLen >> 8) & 0xFF);
            header[11] = (byte) (inclLen & 0xFF);

            header[12] = (byte) ((origLen >> 24) & 0xFF);
            header[13] = (byte) ((origLen >> 16) & 0xFF);
            header[14] = (byte) ((origLen >> 8) & 0xFF);
            header[15] = (byte) (origLen & 0xFF);
        } else {
            header[0] = (byte) (tsSec & 0xFF);
            header[1] = (byte) ((tsSec >> 8) & 0xFF);
            header[2] = (byte) ((tsSec >> 16) & 0xFF);
            header[3] = (byte) ((tsSec >> 24) & 0xFF);

            header[4] = (byte) (tsUsec & 0xFF);
            header[5] = (byte) ((tsUsec >> 8) & 0xFF);
            header[6] = (byte) ((tsUsec >> 16) & 0xFF);
            header[7] = (byte) ((tsUsec >> 24) & 0xFF);

            header[8] = (byte) (inclLen & 0xFF);
            header[9] = (byte) ((inclLen >> 8) & 0xFF);
            header[10] = (byte) ((inclLen >> 16) & 0xFF);
            header[11] = (byte) ((inclLen >> 24) & 0xFF);

            header[12] = (byte) (origLen & 0xFF);
            header[13] = (byte) ((origLen >> 8) & 0xFF);
            header[14] = (byte) ((origLen >> 16) & 0xFF);
            header[15] = (byte) ((origLen >> 24) & 0xFF);
        }
        return header;
    }
}
