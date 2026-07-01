package com.packetanalyzer.service;

import com.packetanalyzer.flow.Connection;
import com.packetanalyzer.flow.ConnectionState;
import com.packetanalyzer.flow.ConnectionTracker;
import com.packetanalyzer.model.AppType;
import com.packetanalyzer.model.PacketAction;
import com.packetanalyzer.model.PacketJob;
import com.packetanalyzer.protocol.DnsExtractor;
import com.packetanalyzer.protocol.HttpHostExtractor;
import com.packetanalyzer.protocol.TlsSniExtractor;
import com.packetanalyzer.rules.BlockReason;
import com.packetanalyzer.rules.RuleManager;

import java.util.Optional;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

public class FastPathProcessor implements Runnable {
    private final int fpId;
    private final BlockingQueue<PacketJob> inputQueue;
    private final ConnectionTracker connTracker;
    private final RuleManager ruleManager;
    private final PacketOutputCallback outputCallback;

    // Statistics
    private final AtomicLong packetsProcessed = new AtomicLong(0);
    private final AtomicLong packetsForwarded = new AtomicLong(0);
    private final AtomicLong packetsDropped = new AtomicLong(0);
    private final AtomicLong sniExtractions = new AtomicLong(0);
    private final AtomicLong classificationHits = new AtomicLong(0);

    private volatile boolean running = false;
    private Thread thread;

    public FastPathProcessor(int fpId, RuleManager ruleManager, PacketOutputCallback outputCallback) {
        this.fpId = fpId;
        this.inputQueue = new ArrayBlockingQueue<>(10000);
        this.connTracker = new ConnectionTracker(fpId);
        this.ruleManager = ruleManager;
        this.outputCallback = outputCallback;
    }

    public int getId() {
        return fpId;
    }

    public BlockingQueue<PacketJob> getInputQueue() {
        return inputQueue;
    }

    public ConnectionTracker getConnectionTracker() {
        return connTracker;
    }

    public void start() {
        if (running) return;
        running = true;
        thread = new Thread(this, "FP-" + fpId);
        thread.start();
        System.out.println("[FP" + fpId + "] Started");
    }

    public void stop() {
        if (!running) return;
        running = false;
        if (thread != null) {
            try {
                thread.join(1000);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
        System.out.println("[FP" + fpId + "] Stopped (processed " + packetsProcessed.get() + " packets)");
    }

    @Override
    public void run() {
        while (running) {
            try {
                PacketJob job = inputQueue.poll(100, TimeUnit.MILLISECONDS);
                if (job == null) {
                    // Periodically cleanup stale connections (similar to C++ 300 seconds stale cleanup)
                    connTracker.cleanupStale(300 * 1000);
                    continue;
                }

                packetsProcessed.incrementAndGet();

                // Process the packet
                PacketAction action = processPacket(job);

                // Call output callback
                if (outputCallback != null) {
                    outputCallback.handle(job, action);
                }

                if (action == PacketAction.DROP) {
                    packetsDropped.incrementAndGet();
                } else {
                    packetsForwarded.incrementAndGet();
                }

            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            }
        }
    }

    private PacketAction processPacket(PacketJob job) {
        Connection conn = connTracker.getOrCreateConnection(job.getTuple());
        if (conn == null) {
            return PacketAction.FORWARD;
        }

        // Update connection statistics
        connTracker.updateConnection(conn, job.getData().length, true);

        // Update TCP connection state
        if (job.getTuple().getProtocol() == 6) { // TCP
            updateTCPState(conn, job.getTcpFlags());
        }

        // If blocked, drop immediately
        if (conn.state == ConnectionState.BLOCKED) {
            return PacketAction.DROP;
        }

        // Try payload classification
        if (conn.state != ConnectionState.CLASSIFIED && job.getPayloadLength() > 0) {
            inspectPayload(job, conn);
        }

        // Check rules
        return checkRules(job, conn);
    }

    private void inspectPayload(PacketJob job, Connection conn) {
        if (job.getPayloadLength() == 0 || job.getPayloadOffset() >= job.getData().length) {
            return;
        }

        byte[] payload = new byte[job.getPayloadLength()];
        System.arraycopy(job.getData(), job.getPayloadOffset(), payload, 0, payload.length);

        // TLS SNI
        if (tryExtractSNI(job, conn, payload)) {
            return;
        }

        // HTTP Host
        if (tryExtractHTTPHost(job, conn, payload)) {
            return;
        }

        // DNS (port 53)
        if (job.getTuple().getDstPort() == 53 || job.getTuple().getSrcPort() == 53) {
            Optional<String> domain = DnsExtractor.extractQuery(payload, payload.length);
            if (domain.isPresent()) {
                connTracker.classifyConnection(conn, AppType.DNS, "");
                return;
            }
        }

        // Fallbacks
        if (job.getTuple().getDstPort() == 80) {
            connTracker.classifyConnection(conn, AppType.HTTP, "");
        } else if (job.getTuple().getDstPort() == 443) {
            connTracker.classifyConnection(conn, AppType.HTTPS, "");
        }
    }

    private boolean tryExtractSNI(PacketJob job, Connection conn, byte[] payload) {
        if (job.getTuple().getDstPort() != 443 && job.getPayloadLength() < 50) {
            return false;
        }

        Optional<String> sni = TlsSniExtractor.extract(payload, payload.length);
        if (sni.isPresent()) {
            sniExtractions.incrementAndGet();
            AppType app = AppType.sniToAppType(sni.get());
            connTracker.classifyConnection(conn, app, sni.get());

            if (app != AppType.UNKNOWN && app != AppType.HTTPS) {
                classificationHits.incrementAndGet();
            }
            return true;
        }
        return false;
    }

    private boolean tryExtractHTTPHost(PacketJob job, Connection conn, byte[] payload) {
        if (job.getTuple().getDstPort() != 80) {
            return false;
        }

        Optional<String> host = HttpHostExtractor.extract(payload, payload.length);
        if (host.isPresent()) {
            AppType app = AppType.sniToAppType(host.get());
            connTracker.classifyConnection(conn, app, host.get());

            if (app != AppType.UNKNOWN && app != AppType.HTTP) {
                classificationHits.incrementAndGet();
            }
            return true;
        }
        return false;
    }

    private PacketAction checkRules(PacketJob job, Connection conn) {
        if (ruleManager == null) {
            return PacketAction.FORWARD;
        }

        Optional<BlockReason> reason = ruleManager.shouldBlock(
                job.getTuple().getSrcIp(),
                job.getTuple().getDstPort(),
                conn.appType,
                conn.sni
        );

        if (reason.isPresent()) {
            BlockReason block = reason.get();
            String reasonType = switch (block.getType()) {
                case IP -> "IP";
                case APP -> "App";
                case DOMAIN -> "Domain";
                case PORT -> "Port";
            };

            System.out.println("[FP" + fpId + "] BLOCKED packet: " + reasonType + " " + block.getDetail());
            connTracker.blockConnection(conn);
            return PacketAction.DROP;
        }

        return PacketAction.FORWARD;
    }

    private void updateTCPState(Connection conn, int tcpFlags) {
        int SYN = 0x02;
        int ACK = 0x10;
        int FIN = 0x01;
        int RST = 0x04;

        if ((tcpFlags & SYN) != 0) {
            if ((tcpFlags & ACK) != 0) {
                conn.synAckSeen = true;
            } else {
                conn.synSeen = true;
            }
        }

        if (conn.synSeen && conn.synAckSeen && (tcpFlags & ACK) != 0) {
            if (conn.state == ConnectionState.NEW) {
                conn.state = ConnectionState.ESTABLISHED;
            }
        }

        if ((tcpFlags & FIN) != 0) {
            conn.finSeen = true;
        }

        if ((tcpFlags & RST) != 0) {
            conn.state = ConnectionState.CLOSED;
        }

        if (conn.finSeen && (tcpFlags & ACK) != 0) {
            conn.state = ConnectionState.CLOSED;
        }
    }

    public FPStats getStats() {
        return new FPStats(
                packetsProcessed.get(),
                packetsForwarded.get(),
                packetsDropped.get(),
                connTracker.getActiveCount(),
                sniExtractions.get(),
                classificationHits.get()
        );
    }

    public static class FPStats {
        public final long packetsProcessed;
        public final long packetsForwarded;
        public final long packetsDropped;
        public final int connectionsTracked;
        public final long sniExtractions;
        public final long classificationHits;

        public FPStats(long packetsProcessed, long packetsForwarded, long packetsDropped,
                       int connectionsTracked, long sniExtractions, long classificationHits) {
            this.packetsProcessed = packetsProcessed;
            this.packetsForwarded = packetsForwarded;
            this.packetsDropped = packetsDropped;
            this.connectionsTracked = connectionsTracked;
            this.sniExtractions = sniExtractions;
            this.classificationHits = classificationHits;
        }
    }
}
