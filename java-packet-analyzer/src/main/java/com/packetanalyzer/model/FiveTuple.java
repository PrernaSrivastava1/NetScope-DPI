package com.packetanalyzer.model;

import java.util.Objects;

public class FiveTuple {
    private final int srcIp;
    private final int dstIp;
    private final int srcPort;
    private final int dstPort;
    private final int protocol; // TCP=6, UDP=17

    public FiveTuple(int srcIp, int dstIp, int srcPort, int dstPort, int protocol) {
        this.srcIp = srcIp;
        this.dstIp = dstIp;
        this.srcPort = srcPort & 0xFFFF;
        this.dstPort = dstPort & 0xFFFF;
        this.protocol = protocol & 0xFF;
    }

    public int getSrcIp() {
        return srcIp;
    }

    public int getDstIp() {
        return dstIp;
    }

    public int getSrcPort() {
        return srcPort;
    }

    public int getDstPort() {
        return dstPort;
    }

    public int getProtocol() {
        return protocol;
    }

    public FiveTuple reverse() {
        return new FiveTuple(dstIp, srcIp, dstPort, srcPort, protocol);
    }

    public static String ipToString(int ip) {
        return ((ip >> 0) & 0xFF) + "." +
               ((ip >> 8) & 0xFF) + "." +
               ((ip >> 16) & 0xFF) + "." +
               ((ip >> 24) & 0xFF);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        FiveTuple other = (FiveTuple) o;
        return srcIp == other.srcIp &&
               dstIp == other.dstIp &&
               srcPort == other.srcPort &&
               dstPort == other.dstPort &&
               protocol == other.protocol;
    }

    @Override
    public int hashCode() {
        return Objects.hash(srcIp, dstIp, srcPort, dstPort, protocol);
    }

    /**
     * Replicates C++ FiveTupleHash logic which is a 64-bit size_t hash.
     * In modern 64-bit GCC/Clang, std::hash for integral values is the identity function.
     * Note that right shift on size_t is unsigned (logical) shift.
     */
    public long getConsistentHash() {
        long h = 0;
        h = hashField(h, srcIp & 0xFFFFFFFFL);
        h = hashField(h, dstIp & 0xFFFFFFFFL);
        h = hashField(h, srcPort);
        h = hashField(h, dstPort);
        h = hashField(h, protocol);
        return h;
    }

    private long hashField(long h, long val) {
        // C++: h ^= std::hash<T>{}(val) + 0x9e3779b9 + (h << 6) + (h >> 2);
        // Note: 0x9e3779b9 is a 32-bit constant, cast to 64-bit.
        // In Java, we use >>> for logical right shift.
        long offset = val + 0x9e3779b9L + (h << 6) + (h >>> 2);
        return h ^ offset;
    }

    @Override
    public String toString() {
        String protoStr = (protocol == 6) ? "TCP" : (protocol == 17) ? "UDP" : "?";
        return ipToString(srcIp) + ":" + srcPort +
               " -> " +
               ipToString(dstIp) + ":" + dstPort +
               " (" + protoStr + ")";
    }
}
