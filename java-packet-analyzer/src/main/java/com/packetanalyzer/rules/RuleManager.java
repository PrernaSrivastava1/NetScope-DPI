package com.packetanalyzer.rules;

import com.packetanalyzer.model.AppType;
import com.packetanalyzer.model.FiveTuple;

import java.io.*;
import java.util.*;
import java.util.concurrent.locks.ReentrantReadWriteLock;

public class RuleManager {

    private final ReentrantReadWriteLock ipLock = new ReentrantReadWriteLock();
    private final Set<Integer> blockedIps = new HashSet<>();

    private final ReentrantReadWriteLock appLock = new ReentrantReadWriteLock();
    private final Set<AppType> blockedApps = new HashSet<>();

    private final ReentrantReadWriteLock domainLock = new ReentrantReadWriteLock();
    private final Set<String> blockedDomains = new HashSet<>();
    private final List<String> domainPatterns = new ArrayList<>(); // Wildcard patterns like *.facebook.com

    private final ReentrantReadWriteLock portLock = new ReentrantReadWriteLock();
    private final Set<Integer> blockedPorts = new HashSet<>();

    // ========== IP Blocking ==========

    public void blockIP(int ip) {
        ipLock.writeLock().lock();
        try {
            blockedIps.add(ip);
            System.out.println("[RuleManager] Blocked IP: " + FiveTuple.ipToString(ip));
        } finally {
            ipLock.writeLock().unlock();
        }
    }

    public void blockIP(String ipStr) {
        blockIP(parseIP(ipStr));
    }

    public void unblockIP(int ip) {
        ipLock.writeLock().lock();
        try {
            blockedIps.remove(ip);
            System.out.println("[RuleManager] Unblocked IP: " + FiveTuple.ipToString(ip));
        } finally {
            ipLock.writeLock().unlock();
        }
    }

    public void unblockIP(String ipStr) {
        unblockIP(parseIP(ipStr));
    }

    public boolean isIPBlocked(int ip) {
        ipLock.readLock().lock();
        try {
            return blockedIps.contains(ip);
        } finally {
            ipLock.readLock().unlock();
        }
    }

    public List<String> getBlockedIPs() {
        ipLock.readLock().lock();
        try {
            List<String> list = new ArrayList<>();
            for (int ip : blockedIps) {
                list.add(FiveTuple.ipToString(ip));
            }
            return list;
        } finally {
            ipLock.readLock().unlock();
        }
    }

    // ========== Application Blocking ==========

    public void blockApp(AppType app) {
        appLock.writeLock().lock();
        try {
            blockedApps.add(app);
            System.out.println("[RuleManager] Blocked app: " + app.getDisplayName());
        } finally {
            appLock.writeLock().unlock();
        }
    }

    public void unblockApp(AppType app) {
        appLock.writeLock().lock();
        try {
            blockedApps.remove(app);
            System.out.println("[RuleManager] Unblocked app: " + app.getDisplayName());
        } finally {
            appLock.writeLock().unlock();
        }
    }

    public boolean isAppBlocked(AppType app) {
        appLock.readLock().lock();
        try {
            return blockedApps.contains(app);
        } finally {
            appLock.readLock().unlock();
        }
    }

    public List<AppType> getBlockedApps() {
        appLock.readLock().lock();
        try {
            return new ArrayList<>(blockedApps);
        } finally {
            appLock.readLock().unlock();
        }
    }

    // ========== Domain Blocking ==========

    public void blockDomain(String domain) {
        domainLock.writeLock().lock();
        try {
            if (domain.contains("*")) {
                domainPatterns.add(domain);
            } else {
                blockedDomains.add(domain);
            }
            System.out.println("[RuleManager] Blocked domain: " + domain);
        } finally {
            domainLock.writeLock().unlock();
        }
    }

    public void unblockDomain(String domain) {
        domainLock.writeLock().lock();
        try {
            if (domain.contains("*")) {
                domainPatterns.remove(domain);
            } else {
                blockedDomains.remove(domain);
            }
            System.out.println("[RuleManager] Unblocked domain: " + domain);
        } finally {
            domainLock.writeLock().unlock();
        }
    }

    private static boolean domainMatchesPattern(String domain, String pattern) {
        if (pattern.length() >= 2 && pattern.startsWith("*.")) {
            String suffix = pattern.substring(1); // .example.com
            if (domain.length() >= suffix.length() && domain.endsWith(suffix)) {
                return true;
            }
            if (domain.equals(pattern.substring(2))) {
                return true;
            }
        }
        return false;
    }

    public boolean isDomainBlocked(String domain) {
        domainLock.readLock().lock();
        try {
            String lowerDomain = domain.toLowerCase();
            for (String blocked : blockedDomains) {
                if (lowerDomain.contains(blocked.toLowerCase())) {
                    return true;
                }
            }

            for (String pattern : domainPatterns) {
                String lowerPattern = pattern.toLowerCase();
                if (domainMatchesPattern(lowerDomain, lowerPattern)) {
                    return true;
                }
            }
            return false;
        } finally {
            domainLock.readLock().unlock();
        }
    }

    public List<String> getBlockedDomains() {
        domainLock.readLock().lock();
        try {
            List<String> list = new ArrayList<>(blockedDomains);
            list.addAll(domainPatterns);
            return list;
        } finally {
            domainLock.readLock().unlock();
        }
    }

    // ========== Port Blocking ==========

    public void blockPort(int port) {
        portLock.writeLock().lock();
        try {
            blockedPorts.add(port);
            System.out.println("[RuleManager] Blocked port: " + port);
        } finally {
            portLock.writeLock().unlock();
        }
    }

    public void unblockPort(int port) {
        portLock.writeLock().lock();
        try {
            blockedPorts.remove(port);
            System.out.println("[RuleManager] Unblocked port: " + port);
        } finally {
            portLock.writeLock().unlock();
        }
    }

    public boolean isPortBlocked(int port) {
        portLock.readLock().lock();
        try {
            return blockedPorts.contains(port);
        } finally {
            portLock.readLock().unlock();
        }
    }

    // ========== Combined Check ==========

    public Optional<BlockReason> shouldBlock(int srcIp, int dstPort, AppType app, String domain) {
        if (isIPBlocked(srcIp)) {
            return Optional.of(new BlockReason(BlockReason.Type.IP, FiveTuple.ipToString(srcIp)));
        }

        if (isPortBlocked(dstPort)) {
            return Optional.of(new BlockReason(BlockReason.Type.PORT, String.valueOf(dstPort)));
        }

        if (isAppBlocked(app)) {
            return Optional.of(new BlockReason(BlockReason.Type.APP, app.getDisplayName()));
        }

        if (domain != null && !domain.isEmpty() && isDomainBlocked(domain)) {
            return Optional.of(new BlockReason(BlockReason.Type.DOMAIN, domain));
        }

        return Optional.empty();
    }

    // ========== Persistence ==========

    public boolean saveRules(String filename) {
        try (PrintWriter writer = new PrintWriter(new BufferedWriter(new FileWriter(filename)))) {
            writer.println("[BLOCKED_IPS]");
            for (String ip : getBlockedIPs()) {
                writer.println(ip);
            }

            writer.println("\n[BLOCKED_APPS]");
            for (AppType app : getBlockedApps()) {
                writer.println(app.getDisplayName());
            }

            writer.println("\n[BLOCKED_DOMAINS]");
            for (String domain : getBlockedDomains()) {
                writer.println(domain);
            }

            writer.println("\n[BLOCKED_PORTS]");
            portLock.readLock().lock();
            try {
                for (int port : blockedPorts) {
                    writer.println(port);
                }
            } finally {
                portLock.readLock().unlock();
            }

            System.out.println("[RuleManager] Rules saved to: " + filename);
            return true;
        } catch (IOException e) {
            System.err.println("[RuleManager] Error saving rules: " + e.getMessage());
            return false;
        }
    }

    public boolean loadRules(String filename) {
        try (BufferedReader reader = new BufferedReader(new FileReader(filename))) {
            String line;
            String currentSection = "";

            while ((line = reader.readLine()) != null) {
                line = line.trim();
                if (line.isEmpty()) continue;

                if (line.startsWith("[")) {
                    currentSection = line;
                    continue;
                }

                switch (currentSection) {
                    case "[BLOCKED_IPS]" -> blockIP(line);
                    case "[BLOCKED_APPS]" -> {
                        AppType app = AppType.fromString(line);
                        if (app != AppType.UNKNOWN) {
                            blockApp(app);
                        } else {
                            System.err.println("[RuleManager] Unknown app in rules file: " + line);
                        }
                    }
                    case "[BLOCKED_DOMAINS]" -> blockDomain(line);
                    case "[BLOCKED_PORTS]" -> blockPort(Integer.parseInt(line));
                }
            }

            System.out.println("[RuleManager] Rules loaded from: " + filename);
            return true;
        } catch (IOException e) {
            System.err.println("[RuleManager] Error loading rules: " + e.getMessage());
            return false;
        }
    }

    public void clearAll() {
        ipLock.writeLock().lock();
        try { blockedIps.clear(); } finally { ipLock.writeLock().unlock(); }

        appLock.writeLock().lock();
        try { blockedApps.clear(); } finally { appLock.writeLock().unlock(); }

        domainLock.writeLock().lock();
        try {
            blockedDomains.clear();
            domainPatterns.clear();
        } finally { domainLock.writeLock().unlock(); }

        portLock.writeLock().lock();
        try { blockedPorts.clear(); } finally { portLock.writeLock().unlock(); }

        System.out.println("[RuleManager] All rules cleared");
    }

    public RuleStats getStats() {
        int ips, apps, domains, ports;

        ipLock.readLock().lock();
        try { ips = blockedIps.size(); } finally { ipLock.readLock().unlock(); }

        appLock.readLock().lock();
        try { apps = blockedApps.size(); } finally { appLock.readLock().unlock(); }

        domainLock.readLock().lock();
        try { domains = blockedDomains.size() + domainPatterns.size(); } finally { domainLock.readLock().unlock(); }

        portLock.readLock().lock();
        try { ports = blockedPorts.size(); } finally { portLock.readLock().unlock(); }

        return new RuleStats(ips, apps, domains, ports);
    }

    public static class RuleStats {
        public final int blockedIps;
        public final int blockedApps;
        public final int blockedDomains;
        public final int blockedPorts;

        public RuleStats(int blockedIps, int blockedApps, int blockedDomains, int blockedPorts) {
            this.blockedIps = blockedIps;
            this.blockedApps = blockedApps;
            this.blockedDomains = blockedDomains;
            this.blockedPorts = blockedPorts;
        }
    }

    public static int parseIP(String ip) {
        int result = 0;
        int octet = 0;
        int shift = 0;
        for (int i = 0; i < ip.length(); i++) {
            char c = ip.charAt(i);
            if (c == '.') {
                result |= (octet << shift);
                shift += 8;
                octet = 0;
            } else if (c >= '0' && c <= '9') {
                octet = octet * 10 + (c - '0');
            }
        }
        result |= (octet << shift);
        return result;
    }
}
