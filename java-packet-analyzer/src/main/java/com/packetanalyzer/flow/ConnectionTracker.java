package com.packetanalyzer.flow;

import com.packetanalyzer.model.AppType;
import com.packetanalyzer.model.FiveTuple;
import com.packetanalyzer.model.PacketAction;

import java.util.*;
import java.util.function.Consumer;

public class ConnectionTracker {
    private final int fpId;
    private final int maxConnections;
    private final Map<FiveTuple, Connection> connections = new HashMap<>();

    // Statistics
    private long totalSeen = 0;
    private long classifiedCount = 0;
    private long blockedCount = 0;

    public ConnectionTracker(int fpId) {
        this(fpId, 100000);
    }

    public ConnectionTracker(int fpId, int maxConnections) {
        this.fpId = fpId;
        this.maxConnections = maxConnections;
    }

    public Connection getOrCreateConnection(FiveTuple tuple) {
        Connection conn = connections.get(tuple);
        if (conn != null) {
            return conn;
        }

        if (connections.size() >= maxConnections) {
            evictOldest();
        }

        conn = new Connection();
        conn.tuple = tuple;
        conn.state = ConnectionState.NEW;
        conn.firstSeen = System.currentTimeMillis();
        conn.lastSeen = conn.firstSeen;

        connections.put(tuple, conn);
        totalSeen++;

        return conn;
    }

    public Connection getConnection(FiveTuple tuple) {
        Connection conn = connections.get(tuple);
        if (conn != null) {
            return conn;
        }

        // Try reverse tuple
        return connections.get(tuple.reverse());
    }

    public void updateConnection(Connection conn, int packetSize, boolean isOutbound) {
        if (conn == null) return;

        conn.lastSeen = System.currentTimeMillis();

        if (isOutbound) {
            conn.packetsOut++;
            conn.bytesOut += packetSize;
        } else {
            conn.packetsIn++;
            conn.bytesIn += packetSize;
        }
    }

    public void classifyConnection(Connection conn, AppType app, String sni) {
        if (conn == null) return;

        if (conn.state != ConnectionState.CLASSIFIED) {
            conn.appType = app;
            conn.sni = sni;
            conn.state = ConnectionState.CLASSIFIED;
            classifiedCount++;
        }
    }

    public void blockConnection(Connection conn) {
        if (conn == null) return;

        conn.state = ConnectionState.BLOCKED;
        conn.action = PacketAction.DROP;
        blockedCount++;
    }

    public void closeConnection(FiveTuple tuple) {
        Connection conn = connections.get(tuple);
        if (conn != null) {
            conn.state = ConnectionState.CLOSED;
        }
    }

    public int cleanupStale(long timeoutMillis) {
        long now = System.currentTimeMillis();
        int removed = 0;

        Iterator<Map.Entry<FiveTuple, Connection>> iterator = connections.entrySet().iterator();
        while (iterator.hasNext()) {
            Map.Entry<FiveTuple, Connection> entry = iterator.next();
            Connection conn = entry.getValue();

            long age = now - conn.lastSeen;
            if (age > timeoutMillis || conn.state == ConnectionState.CLOSED) {
                iterator.remove();
                removed++;
            }
        }

        return removed;
    }

    public List<Connection> getAllConnections() {
        return new ArrayList<>(connections.values());
    }

    public int getActiveCount() {
        return connections.size();
    }

    public TrackerStats getStats() {
        return new TrackerStats(connections.size(), totalSeen, classifiedCount, blockedCount);
    }

    public void clear() {
        connections.clear();
    }

    public void forEach(Consumer<Connection> callback) {
        for (Connection conn : connections.values()) {
            callback.accept(conn);
        }
    }

    private void evictOldest() {
        if (connections.isEmpty()) return;

        FiveTuple oldestKey = null;
        long oldestTime = Long.MAX_VALUE;

        for (Map.Entry<FiveTuple, Connection> entry : connections.entrySet()) {
            if (entry.getValue().lastSeen < oldestTime) {
                oldestTime = entry.getValue().lastSeen;
                oldestKey = entry.getKey();
            }
        }

        if (oldestKey != null) {
            connections.remove(oldestKey);
        }
    }

    public static class TrackerStats {
        public final int activeConnections;
        public final long totalConnectionsSeen;
        public final long classifiedConnections;
        public final long blockedConnections;

        public TrackerStats(int activeConnections, long totalConnectionsSeen,
                            long classifiedConnections, long blockedConnections) {
            this.activeConnections = activeConnections;
            this.totalConnectionsSeen = totalConnectionsSeen;
            this.classifiedConnections = classifiedConnections;
            this.blockedConnections = blockedConnections;
        }
    }
}
