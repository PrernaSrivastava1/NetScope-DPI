package com.packetanalyzer.flow;

import com.packetanalyzer.model.AppType;
import com.packetanalyzer.model.FiveTuple;
import org.junit.jupiter.api.Test;
import java.util.List;
import static org.junit.jupiter.api.Assertions.*;

public class ConnectionTrackerTest {

    @Test
    public void testConnectionTracking() {
        ConnectionTracker tracker = new ConnectionTracker(0, 100);

        FiveTuple tuple = new FiveTuple(1, 2, 80, 50000, 6);
        Connection conn = tracker.getOrCreateConnection(tuple);
        assertNotNull(conn);
        assertEquals(ConnectionState.NEW, conn.state);
        assertEquals(tuple, conn.tuple);

        // Retrieve existing
        Connection retrieved = tracker.getConnection(tuple);
        assertSame(conn, retrieved);

        // Update statistics
        tracker.updateConnection(conn, 100, true);  // Outbound
        tracker.updateConnection(conn, 200, false); // Inbound
        assertEquals(1, conn.packetsOut);
        assertEquals(1, conn.packetsIn);
        assertEquals(100, conn.bytesOut);
        assertEquals(200, conn.bytesIn);

        // Classify
        tracker.classifyConnection(conn, AppType.GOOGLE, "google.com");
        assertEquals(ConnectionState.CLASSIFIED, conn.state);
        assertEquals(AppType.GOOGLE, conn.appType);
        assertEquals("google.com", conn.sni);

        // Stats check
        ConnectionTracker.TrackerStats stats = tracker.getStats();
        assertEquals(1, stats.activeConnections);
        assertEquals(1, stats.totalConnectionsSeen);
        assertEquals(1, stats.classifiedConnections);
        assertEquals(0, stats.blockedConnections);

        // Block connection
        tracker.blockConnection(conn);
        assertEquals(ConnectionState.BLOCKED, conn.state);
        assertEquals(1, tracker.getStats().blockedConnections);
    }

    @Test
    public void testCleanupAndEviction() throws InterruptedException {
        // Capacity of 2
        ConnectionTracker tracker = new ConnectionTracker(0, 2);

        FiveTuple t1 = new FiveTuple(1, 2, 80, 50000, 6);
        FiveTuple t2 = new FiveTuple(3, 4, 80, 50001, 6);
        FiveTuple t3 = new FiveTuple(5, 6, 80, 50002, 6);

        tracker.getOrCreateConnection(t1);
        Thread.sleep(2);
        tracker.getOrCreateConnection(t2);

        assertEquals(2, tracker.getActiveCount());

        // This triggers eviction of oldest connection (which is t1)
        tracker.getOrCreateConnection(t3);
        assertEquals(2, tracker.getActiveCount());
        assertNull(tracker.getConnection(t1));
        assertNotNull(tracker.getConnection(t2));
        assertNotNull(tracker.getConnection(t3));

        // Test cleanup of stale connection (set timeout of 0ms to clean everything)
        int cleaned = tracker.cleanupStale(-1);
        assertEquals(2, cleaned);
        assertEquals(0, tracker.getActiveCount());
    }

    @Test
    public void testGlobalConnectionTable() {
        GlobalConnectionTable globalTable = new GlobalConnectionTable(2);

        ConnectionTracker tracker0 = new ConnectionTracker(0);
        ConnectionTracker tracker1 = new ConnectionTracker(1);

        globalTable.registerTracker(0, tracker0);
        globalTable.registerTracker(1, tracker1);

        FiveTuple t1 = new FiveTuple(1, 2, 80, 50000, 6);
        Connection conn1 = tracker0.getOrCreateConnection(t1);
        tracker0.classifyConnection(conn1, AppType.GOOGLE, "google.com");

        FiveTuple t2 = new FiveTuple(3, 4, 443, 50001, 6);
        Connection conn2 = tracker1.getOrCreateConnection(t2);
        tracker1.classifyConnection(conn2, AppType.YOUTUBE, "youtube.com");

        GlobalConnectionTable.GlobalStats stats = globalTable.getGlobalStats();
        assertEquals(2, stats.totalActiveConnections);
        assertEquals(2, stats.totalConnectionsSeen);
        assertEquals(1L, stats.appDistribution.get(AppType.GOOGLE));
        assertEquals(1L, stats.appDistribution.get(AppType.YOUTUBE));

        String report = globalTable.generateReport();
        assertNotNull(report);
        assertTrue(report.contains("CONNECTION STATISTICS REPORT"));
        assertTrue(report.contains("Google"));
        assertTrue(report.contains("YouTube"));
        assertTrue(report.contains("google.com"));
        assertTrue(report.contains("youtube.com"));
    }
}
