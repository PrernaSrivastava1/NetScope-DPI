package com.packetanalyzer.model;

import java.util.concurrent.atomic.AtomicLong;

public class DPIStats {
    public final AtomicLong totalPackets = new AtomicLong(0);
    public final AtomicLong totalBytes = new AtomicLong(0);
    public final AtomicLong forwardedPackets = new AtomicLong(0);
    public final AtomicLong droppedPackets = new AtomicLong(0);
    public final AtomicLong tcpPackets = new AtomicLong(0);
    public final AtomicLong udpPackets = new AtomicLong(0);
    public final AtomicLong otherPackets = new AtomicLong(0);
    public final AtomicLong activeConnections = new AtomicLong(0);

    public void reset() {
        totalPackets.set(0);
        totalBytes.set(0);
        forwardedPackets.set(0);
        droppedPackets.set(0);
        tcpPackets.set(0);
        udpPackets.set(0);
        otherPackets.set(0);
        activeConnections.set(0);
    }
}
