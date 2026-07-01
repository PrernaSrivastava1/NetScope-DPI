package com.packetanalyzer.utils;

import com.packetanalyzer.model.FiveTuple;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

public class ConsistentHashTest {

    @Test
    public void testHashConsistency() {
        // Mock a 5-tuple: 192.168.1.100 (src) -> 142.250.185.206 (dst) on TCP (6)
        // 192.168.1.100 in little endian representation:
        // Byte 0: 192 (0xC0)
        // Byte 1: 168 (0xA8)
        // Byte 2: 1   (0x01)
        // Byte 3: 100 (0x64)
        // Value: 0x6401a8c0 = 1677830336
        int srcIp = 1677830336;

        // 142.250.185.206:
        // Byte 0: 142 (0x8E)
        // Byte 1: 250 (0xFA)
        // Byte 2: 185 (0xB9)
        // Byte 3: 206 (0xCE)
        // Value: 0xCEB9FA8E = -826672498 (signed int in Java)
        int dstIp = (206 << 24) | (185 << 16) | (250 << 8) | 142;

        int srcPort = 54321;
        int dstPort = 443;
        int protocol = 6;

        FiveTuple tuple = new FiveTuple(srcIp, dstIp, srcPort, dstPort, protocol);

        long hash = tuple.getConsistentHash();
        
        // Assert that the hash is deterministic and doesn't change
        assertEquals(hash, tuple.getConsistentHash());

        // Verify reverse tuple has different hash but works consistently
        FiveTuple reversed = tuple.reverse();
        assertNotEquals(hash, reversed.getConsistentHash());

        // Select LB index
        int numLbs = 2;
        int lbIdx = ConsistentHash.getLBIndex(tuple, numLbs);
        assertTrue(lbIdx >= 0 && lbIdx < numLbs);

        int numFps = 4;
        int fpIdx = ConsistentHash.getFPIndex(tuple, numFps);
        assertTrue(fpIdx >= 0 && fpIdx < numFps);
    }
}
