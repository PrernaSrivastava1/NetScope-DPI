package com.packetanalyzer.service;

import com.packetanalyzer.flow.Connection;
import com.packetanalyzer.model.AppType;
import com.packetanalyzer.model.PacketJob;
import com.packetanalyzer.rules.RuleManager;

import java.util.*;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.atomic.AtomicLong;

public class FPManager {
    private final List<FastPathProcessor> fps = new ArrayList<>();

    public FPManager(int numFps, RuleManager ruleManager, PacketOutputCallback outputCallback) {
        for (int i = 0; i < numFps; i++) {
            fps.add(new FastPathProcessor(i, ruleManager, outputCallback));
        }
        System.out.println("[FPManager] Created " + numFps + " fast path processors");
    }

    public void startAll() {
        for (FastPathProcessor fp : fps) {
            fp.start();
        }
    }

    public void stopAll() {
        for (FastPathProcessor fp : fps) {
            fp.stop();
        }
    }

    public FastPathProcessor getFP(int id) {
        return fps.get(id);
    }

    public BlockingQueue<PacketJob> getFPQueue(int id) {
        return fps.get(id).getInputQueue();
    }

    public List<BlockingQueue<PacketJob>> getQueuePtrs() {
        List<BlockingQueue<PacketJob>> queues = new ArrayList<>();
        for (FastPathProcessor fp : fps) {
            queues.add(fp.getInputQueue());
        }
        return queues;
    }

    public int getNumFPs() {
        return fps.size();
    }

    public AggregatedFPStats getAggregatedStats() {
        long totalProcessed = 0;
        long totalForwarded = 0;
        long totalDropped = 0;
        long totalConnections = 0;

        for (FastPathProcessor fp : fps) {
            FastPathProcessor.FPStats stats = fp.getStats();
            totalProcessed += stats.packetsProcessed;
            totalForwarded += stats.packetsForwarded;
            totalDropped += stats.packetsDropped;
            totalConnections += stats.connectionsTracked;
        }

        return new AggregatedFPStats(totalProcessed, totalForwarded, totalDropped, totalConnections);
    }

    public String generateClassificationReport() {
        Map<AppType, Long> appCounts = new HashMap<>();
        Map<String, Long> domainCounts = new HashMap<>();
        long totalClassified = 0;
        long totalUnknown = 0;

        for (FastPathProcessor fp : fps) {
            List<Connection> conns = fp.getConnectionTracker().getAllConnections();
            for (Connection conn : conns) {
                appCounts.put(conn.appType, appCounts.getOrDefault(conn.appType, 0L) + 1);

                if (conn.appType == AppType.UNKNOWN) {
                    totalUnknown++;
                } else {
                    totalClassified++;
                }

                if (conn.sni != null && !conn.sni.isEmpty()) {
                    domainCounts.put(conn.sni, domainCounts.getOrDefault(conn.sni, 0L) + 1);
                }
            }
        }

        StringBuilder sb = new StringBuilder();
        sb.append("\n╔══════════════════════════════════════════════════════════════╗\n");
        sb.append("║                 APPLICATION CLASSIFICATION REPORT             ║\n");
        sb.append("╠══════════════════════════════════════════════════════════════╣\n");

        long total = totalClassified + totalUnknown;
        double classifiedPct = total > 0 ? (100.0 * totalClassified / total) : 0.0;
        double unknownPct = total > 0 ? (100.0 * totalUnknown / total) : 0.0;

        sb.append(String.format("║ Total Connections:    %10d                           ║\n", total));
        sb.append(String.format("║ Classified:           %10d (%5.1f%%)                  ║\n", totalClassified, classifiedPct));
        sb.append(String.format("║ Unidentified:         %10d (%5.1f%%)                  ║\n", totalUnknown, unknownPct));
        sb.append("╠══════════════════════════════════════════════════════════════╣\n");
        sb.append("║                    APPLICATION DISTRIBUTION                   ║\n");
        sb.append("╠══════════════════════════════════════════════════════════════╣\n");

        // Sort apps by count descending
        List<Map.Entry<AppType, Long>> sortedApps = new ArrayList<>(appCounts.entrySet());
        sortedApps.sort((a, b) -> b.getValue().compareTo(a.getValue()));

        for (Map.Entry<AppType, Long> entry : sortedApps) {
            double pct = total > 0 ? (100.0 * entry.getValue() / total) : 0.0;
            int barLen = (int) (pct / 5.0); // 20 chars max for 100%
            String bar = "#".repeat(barLen);
            String barFormat = String.format("%-20s", bar); // pad to 20 chars

            sb.append(String.format("║ %-15s%8d %5.1f%% %s   ║\n",
                    entry.getKey().getDisplayName(), entry.getValue(), pct, barFormat));
        }

        sb.append("╚══════════════════════════════════════════════════════════════╝\n");
        return sb.toString();
    }

    public static class AggregatedFPStats {
        public final long totalProcessed;
        public final long totalForwarded;
        public final long totalDropped;
        public final long totalConnections;

        public AggregatedFPStats(long totalProcessed, long totalForwarded, long totalDropped, long totalConnections) {
            this.totalProcessed = totalProcessed;
            this.totalForwarded = totalForwarded;
            this.totalDropped = totalDropped;
            this.totalConnections = totalConnections;
        }
    }
}
