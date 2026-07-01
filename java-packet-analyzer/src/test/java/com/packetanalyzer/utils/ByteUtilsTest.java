package com.packetanalyzer.utils;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

public class ByteUtilsTest {

    @Test
    public void testByteReadHelpers() {
        byte[] testData = new byte[] {
            (byte) 0x12, (byte) 0x34, (byte) 0x56, (byte) 0x78, (byte) 0x90
        };

        // Big-endian 16-bit
        int val16BE = ByteUtils.readUint16BE(testData, 0);
        assertEquals(0x1234, val16BE);

        // Little-endian 16-bit
        int val16LE = ByteUtils.readUint16LE(testData, 0);
        assertEquals(0x3412, val16LE);

        // Big-endian 32-bit
        long val32BE = ByteUtils.readUint32BE(testData, 0);
        assertEquals(0x12345678L, val32BE);

        // Little-endian 32-bit
        long val32LE = ByteUtils.readUint32LE(testData, 0);
        assertEquals(0x78563412L, val32LE);

        // Big-endian 24-bit
        int val24BE = ByteUtils.readUint24BE(testData, 1);
        assertEquals(0x345678, val24BE);
    }

    @Test
    public void testByteSwapping() {
        assertEquals(0x3412, ByteUtils.swap16(0x1234));
        assertEquals(0x78563412, ByteUtils.swap32(0x12345678));
    }
}
