package com.packetanalyzer.flow;

import com.packetanalyzer.model.AppType;

import java.util.*;
import java.util.concurrent.locks.ReentrantReadWriteLock;

public class GlobalConnectionTable {
    private final List<ConnectionTracker> trackers;
    private final ReentrantReadWriteLock lock = new ReentrantReadWriteLock();

    public GlobalConnectionTable(int numFps) {
        this.trackers = new ArrayList<>(Collections.nCopies(numFps, null));
    }

    public void registerTracker(int fpId, ConnectionTracker tracker) {
        lock.writeLock().lock();
        try {
            if (fpId >= 0 && fpId < trackers.size()) {
                trackers.set(fpId, tracker);
            }
        } finally {
            lock.writeLock().unlock();
        }
    }

    public GlobalStats getGlobalStats() {
        lock.readLock().lock();
        try {
            int totalActiveConnections = 0;
            long totalConnectionsSeen = 0;
            Map<AppType, Long> appDistribution = new HashMap<>();
            Map<String, Long> domainCounts = new HashMap<>();

            for (ConnectionTracker tracker : trackers) {
                if (tracker == null) continue;

                ConnectionTracker.TrackerStats trackerStats = tracker.getStats();
                totalActiveConnections += trackerStats.activeConnections;
                totalConnectionsSeen += trackerStats.totalConnectionsSeen;

                // Collect app distribution & domains
                tracker.forEach(conn -> {
                    appDistribution.put(conn.appType, appDistribution.getOrDefault(conn.appType, 0L) + 1);
                    if (conn.sni != null && !conn.sni.isEmpty()) {
                        domainCounts.put(conn.sni, domainCounts.getOrDefault(conn.sni, 0L) + 1);
                    }
                });
            }

            // Sort domains by count descending
            List<Map.Entry<String, Long>> domainList = new ArrayList<>(domainCounts.entrySet());
            domainList.sort((a, b) -> b.getValue().compareTo(a.getValue()));

            // Take top 20
            List<Map.Entry<String, Long>> topDomains = new ArrayList<>();
            for (int i = 0; i < Math.min(domainList.size(), 20); i++) {
                topDomains.add(domainList.get(i));
            }

            return new GlobalStats(totalActiveConnections, totalConnectionsSeen, appDistribution, topDomains);
        } finally {
            lock.readLock().unlock();
        }
    }

    public String generateReport() {
        GlobalStats stats = getGlobalStats();
        StringBuilder sb = new StringBuilder();

        sb.append("\n╔══════════════════════════════════════════════════════════════╗\n");
        sb.append("║               CONNECTION STATISTICS REPORT                    ║\n");
        sb.append("╠══════════════════════════════════════════════════════════════╣\n");
        sb.append(String.format("║ Active Connections:     %10d                          ║\n", stats.totalActiveConnections));
        sb.append(String.format("║ Total Connections Seen: %10d                          ║\n", stats.totalConnectionsSeen));
        sb.append("╠══════════════════════════════════════════════════════════════╣\n");
        sb.append("║                    APPLICATION BREAKDOWN                      ║\n");
        sb.append("╠══════════════════════════════════════════════════════════════╣\n");

        long totalApps = 0;
        for (long count : stats.appDistribution.values()) {
            totalApps += count;
        }

        // Sort apps by count descending
        List<Map.Entry<AppType, Long>> sortedApps = new ArrayList<>(stats.appDistribution.entrySet());
        sortedApps.sort((a, b) -> b.getValue().compareTo(a.getValue()));

        for (Map.Entry<AppType, Long> entry : sortedApps) {
            double pct = totalApps > 0 ? (100.0 * entry.getValue() / totalApps) : 0.0;
            sb.append(String.format("║ %-20s%10d (%5.1f%%)           ║\n",
                    entry.getKey().getDisplayName(), entry.getValue(), pct));
        }

        if (!stats.topDomains.isEmpty()) {
            sb.append("╠══════════════════════════════════════════════════════════════╣\n");
            sb.append("║                      TOP DOMAINS                             ║\n");
            sb.append("╠══════════════════════════════════════════════════════════════╣\n");

            for (Map.Entry<String, Long> entry : stats.topDomains) {
                String domain = entry.getKey();
                if (domain.length() > 35) {
                    domain = domain.substring(0, 32) + "...";
                }
                sb.append(String.format("║ %-40s%10d           ║\n", domain, entry.getValue()));
            }
        }

        sb.append("╚══════════════════════════════════════════════════════════════╝\n");
        return sb.toString();
    }

    public static class GlobalStats {
        public final int totalActiveConnections;
        public final long totalConnectionsSeen;
        public final Map<AppType, Long> appDistribution;
        public final List<Map.Entry<String, Long>> topDomains;

        public GlobalStats(int totalActiveConnections, long totalConnectionsSeen,
                           Map<AppType, Long> appDistribution, List<Map.Entry<String, Long>> topDomains) {
            this.totalActiveConnections = totalActiveConnections;
            this.totalConnectionsSeen = totalConnectionsSeen;
            this.appDistribution = appDistribution;
            this.topDomains = topDomains;
        }
    }
}
