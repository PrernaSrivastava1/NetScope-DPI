package com.packetanalyzer.service;

import com.packetanalyzer.config.DPIEngineConfig;
import com.packetanalyzer.flow.GlobalConnectionTable;
import com.packetanalyzer.model.AppType;
import com.packetanalyzer.model.FiveTuple;
import com.packetanalyzer.model.PacketAction;
import com.packetanalyzer.model.PacketJob;
import com.packetanalyzer.model.DPIStats;
import com.packetanalyzer.model.RawPacket;
import com.packetanalyzer.model.ParsedPacket;
import com.packetanalyzer.parser.PcapReader;
import com.packetanalyzer.parser.PacketParser;
import com.packetanalyzer.rules.RuleManager;
import com.packetanalyzer.utils.ByteUtils;

import java.io.*;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

public class DPIEngine {
    private final DPIEngineConfig config;
    private RuleManager ruleManager;
    private GlobalConnectionTable globalConnTable;
    private FPManager fpManager;
    private LBManager lbManager;

    private final BlockingQueue<PacketJob> outputQueue;
    private final DPIStats stats = new DPIStats();

    private final AtomicBoolean running = new AtomicBoolean(false);
    private final AtomicBoolean processingComplete = new AtomicBoolean(false);

    private Thread outputThread;
    private Thread readerThread;
    private OutputStream outputStream;
    private boolean bigEndianOutput = false;

    public DPIEngine(DPIEngineConfig config) {
        this.config = config;
        this.outputQueue = new ArrayBlockingQueue<>(10000);
        this.ruleManager = new RuleManager();

        int totalFps = config.numLoadBalancers * config.fpsPerLb;
        System.out.println("\n");
        System.out.println("╔══════════════════════════════════════════════════════════════╗");
        System.out.println("║                    DPI ENGINE v1.0                            ║");
        System.out.println("║               Deep Packet Inspection System                   ║");
        System.out.println("╠══════════════════════════════════════════════════════════════╣");
        System.out.println("║ Configuration:                                                ║");
        System.out.println(String.format("║   Load Balancers:    %3d                                       ║", config.numLoadBalancers));
        System.out.println(String.format("║   FPs per LB:        %3d                                       ║", config.fpsPerLb));
        System.out.println(String.format("║   Total FP threads:  %3d                                       ║", totalFps));
        System.out.println("╚══════════════════════════════════════════════════════════════╝");
    }

    public boolean initialize() {
        if (config.rulesFile != null && !config.rulesFile.isEmpty()) {
            ruleManager.loadRules(config.rulesFile);
        }

        int totalFps = config.numLoadBalancers * config.fpsPerLb;

        PacketOutputCallback outputCb = this::handleOutput;

        fpManager = new FPManager(totalFps, ruleManager, outputCb);
        lbManager = new LBManager(config.numLoadBalancers, config.fpsPerLb, fpManager.getQueuePtrs());

        globalConnTable = new GlobalConnectionTable(totalFps);
        for (int i = 0; i < totalFps; i++) {
            globalConnTable.registerTracker(i, fpManager.getFP(i).getConnectionTracker());
        }

        System.out.println("[DPIEngine] Initialized successfully");
        return true;
    }

    public void start() {
        if (running.get()) return;
        running.set(true);
        processingComplete.set(false);

        // Start output thread
        outputThread = new Thread(this::outputThreadFunc, "Output-Writer");
        outputThread.start();

        // Start processors
        fpManager.startAll();
        lbManager.startAll();

        System.out.println("[DPIEngine] All threads started");
    }

    public void stop() {
        if (!running.get()) return;
        running.set(false);

        // Stop LB threads (feeds FPs)
        if (lbManager != null) {
            lbManager.stopAll();
        }

        // Stop FPs
        if (fpManager != null) {
            fpManager.stopAll();
        }

        // Stop output writer
        if (outputThread != null) {
            try {
                outputThread.join(1000);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }

        System.out.println("[DPIEngine] All threads stopped");
    }

    public void waitForCompletion() {
        if (readerThread != null) {
            try {
                readerThread.join();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }

        // Wait for queues to drain
        try {
            Thread.sleep(500);
        } catch (InterruptedException ignored) {}

        processingComplete.set(true);
    }

    public boolean processFile(String inputFile, String outputFile) {
        System.out.println("\n[DPIEngine] Processing: " + inputFile);
        System.out.println("[DPIEngine] Output to:  " + outputFile + "\n");

        if (fpManager == null) {
            if (!initialize()) {
                return false;
            }
        }

        try {
            outputStream = new BufferedOutputStream(new FileOutputStream(outputFile));
        } catch (FileNotFoundException e) {
            System.err.println("[DPIEngine] Error: Cannot open output file");
            return false;
        }

        // Start processing threads
        start();

        // Start reader thread
        readerThread = new Thread(() -> readerThreadFunc(inputFile), "Reader-Thread");
        readerThread.start();

        // Wait for completion
        waitForCompletion();

        // Wait for final packets
        try {
            Thread.sleep(200);
        } catch (InterruptedException ignored) {}

        // Stop all threads
        stop();

        // Close output file
        if (outputStream != null) {
            try {
                outputStream.close();
            } catch (IOException ignored) {}
        }

        // Print final reports
        System.out.print(generateReport());
        System.out.print(fpManager.generateClassificationReport());

        return true;
    }

    private void readerThreadFunc(String inputFile) {
        try (PcapReader reader = new PcapReader()) {
            if (!reader.open(inputFile)) {
                System.err.println("[Reader] Error: Cannot open input file");
                return;
            }

            // Set endianness of output packet headers
            bigEndianOutput = reader.needsByteSwap();

            // Write PCAP global header to output file
            writeOutputHeader(reader.getGlobalHeaderBytes());

            RawPacket[] rawRef = new RawPacket[1];
            ParsedPacket parsed = new ParsedPacket();
            int packetId = 0;

            System.out.println("[Reader] Starting packet processing...");

            while (reader.readNextPacket(rawRef)) {
                RawPacket raw = rawRef[0];
                if (!PacketParser.parse(raw, parsed)) {
                    continue; // Skip unparseable packets
                }

                // Only process IP packets with TCP or UDP
                if (!parsed.isHasIp() || (!parsed.isHasTcp() && !parsed.isHasUdp())) {
                    continue;
                }

                // Create packet job
                PacketJob job = createPacketJob(raw, parsed, packetId++);

                // Update global stats
                stats.totalPackets.incrementAndGet();
                stats.totalBytes.addAndGet(raw.getData().length);

                if (parsed.isHasTcp()) {
                    stats.tcpPackets.incrementAndGet();
                } else if (parsed.isHasUdp()) {
                    stats.udpPackets.incrementAndGet();
                }

                // Dispatch to appropriate LB based on hash
                LoadBalancer lb = lbManager.getLBForPacket(job.getTuple());
                lb.getInputQueue().put(job);
            }

            System.out.println("[Reader] Finished reading " + packetId + " packets");
        } catch (Exception e) {
            System.err.println("[Reader] Exception occurred: " + e.getMessage());
        }
    }

    private PacketJob createPacketJob(RawPacket raw, ParsedPacket parsed, int packetId) {
        PacketJob job = new PacketJob();
        job.setPacketId(packetId);
        job.setTsSec(raw.getHeader().getTsSec());
        job.setTsUsec(raw.getHeader().getTsUsec());
        job.setTcpFlags(parsed.getTcpFlags());
        job.setData(raw.getData());

        // Parse 5-tuple
        int srcIp = RuleManager.parseIP(parsed.getSrcIp());
        int dstIp = RuleManager.parseIP(parsed.getDestIp());
        FiveTuple tuple = new FiveTuple(srcIp, dstIp, parsed.getSrcPort(), parsed.getDestPort(), parsed.getProtocol());
        job.setTuple(tuple);

        // Calculate offsets
        job.setEthOffset(0);
        job.setIpOffset(14); // Ethernet header is 14 bytes

        if (job.getData().length > 14) {
            int ipIhl = job.getData()[14] & 0x0F;
            int ipHeaderLen = ipIhl * 4;
            job.setTransportOffset(14 + ipHeaderLen);

            if (parsed.isHasTcp() && job.getData().length > job.getTransportOffset()) {
                int tcpDataOffset = ((job.getData()[job.getTransportOffset() + 12] & 0xFF) >> 4) & 0x0F;
                int tcpHeaderLen = tcpDataOffset * 4;
                job.setPayloadOffset(job.getTransportOffset() + tcpHeaderLen);
            } else if (parsed.isHasUdp()) {
                job.setPayloadOffset(job.getTransportOffset() + 8); // UDP is 8 bytes
            }

            if (job.getPayloadOffset() < job.getData().length) {
                job.setPayloadLength(job.getData().length - job.getPayloadOffset());
            } else {
                job.setPayloadLength(0);
            }
        }

        return job;
    }

    private void outputThreadFunc() {
        while (running.get() || !outputQueue.isEmpty()) {
            try {
                PacketJob job = outputQueue.poll(100, TimeUnit.MILLISECONDS);
                if (job != null) {
                    writeOutputPacket(job);
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            }
        }
    }

    private void handleOutput(PacketJob job, PacketAction action) {
        if (action == PacketAction.DROP) {
            stats.droppedPackets.incrementAndGet();
            return;
        }

        stats.forwardedPackets.incrementAndGet();
        try {
            outputQueue.put(job);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    private synchronized void writeOutputHeader(byte[] header) {
        if (outputStream == null) return;
        try {
            outputStream.write(header);
            outputStream.flush();
        } catch (IOException e) {
            System.err.println("Error writing PCAP header: " + e.getMessage());
        }
    }

    private synchronized void writeOutputPacket(PacketJob job) {
        if (outputStream == null) return;
        try {
            byte[] header = ByteUtils.serializePacketHeader(
                    job.getTsSec(), job.getTsUsec(), job.getData().length, job.getData().length, bigEndianOutput
            );
            outputStream.write(header);
            outputStream.write(job.getData());
        } catch (IOException e) {
            System.err.println("Error writing packet: " + e.getMessage());
        }
    }

    // ========== Rules APIs ==========

    public void blockIP(String ip) { if (ruleManager != null) ruleManager.blockIP(ip); }
    public void unblockIP(String ip) { if (ruleManager != null) ruleManager.unblockIP(ip); }
    public void blockApp(String appName) { if (ruleManager != null) ruleManager.blockApp(AppType.fromString(appName)); }
    public void unblockApp(String appName) { if (ruleManager != null) ruleManager.unblockApp(AppType.fromString(appName)); }
    public void blockDomain(String domain) { if (ruleManager != null) ruleManager.blockDomain(domain); }
    public void unblockDomain(String domain) { if (ruleManager != null) ruleManager.unblockDomain(domain); }
    public boolean loadRules(String filename) { return ruleManager != null && ruleManager.loadRules(filename); }
    public boolean saveRules(String filename) { return ruleManager != null && ruleManager.saveRules(filename); }

    // ========== Reporting ==========

    public String generateReport() {
        StringBuilder sb = new StringBuilder();
        sb.append("\n╔══════════════════════════════════════════════════════════════╗\n");
        sb.append("║                    DPI ENGINE STATISTICS                      ║\n");
        sb.append("╠══════════════════════════════════════════════════════════════╣\n");
        sb.append("║ PACKET STATISTICS                                             ║\n");
        sb.append(String.format("║   Total Packets:      %12d                        ║\n", stats.totalPackets.get()));
        sb.append(String.format("║   Total Bytes:        %12d                        ║\n", stats.totalBytes.get()));
        sb.append(String.format("║   TCP Packets:        %12d                        ║\n", stats.tcpPackets.get()));
        sb.append(String.format("║   UDP Packets:        %12d                        ║\n", stats.udpPackets.get()));
        sb.append("╠══════════════════════════════════════════════════════════════╣\n");
        sb.append("║ FILTERING STATISTICS                                          ║\n");
        sb.append(String.format("║   Forwarded:          %12d                        ║\n", stats.forwardedPackets.get()));
        sb.append(String.format("║   Dropped/Blocked:    %12d                        ║\n", stats.droppedPackets.get()));

        if (stats.totalPackets.get() > 0) {
            double dropRate = 100.0 * stats.droppedPackets.get() / stats.totalPackets.get();
            sb.append(String.format("║   Drop Rate:          %11.2f%%                        ║\n", dropRate));
        }

        if (lbManager != null) {
            LBManager.AggregatedLBStats lbStats = lbManager.getAggregatedStats();
            sb.append("╠══════════════════════════════════════════════════════════════╣\n");
            sb.append("║ LOAD BALANCER STATISTICS                                      ║\n");
            sb.append(String.format("║   LB Received:        %12d                        ║\n", lbStats.totalReceived));
            sb.append(String.format("║   LB Dispatched:      %12d                        ║\n", lbStats.totalDispatched));
        }

        if (fpManager != null) {
            FPManager.AggregatedFPStats fpStats = fpManager.getAggregatedStats();
            sb.append("╠══════════════════════════════════════════════════════════════╣\n");
            sb.append("║ FAST PATH STATISTICS                                          ║\n");
            sb.append(String.format("║   FP Processed:       %12d                        ║\n", fpStats.totalProcessed));
            sb.append(String.format("║   FP Forwarded:       %12d                        ║\n", fpStats.totalForwarded));
            sb.append(String.format("║   FP Dropped:         %12d                        ║\n", fpStats.totalDropped));
            sb.append(String.format("║   Active Connections: %12d                        ║\n", fpStats.totalConnections));
        }

        if (ruleManager != null) {
            RuleManager.RuleStats ruleStats = ruleManager.getStats();
            sb.append("╠══════════════════════════════════════════════════════════════╣\n");
            sb.append("║ BLOCKING RULES                                                ║\n");
            sb.append(String.format("║   Blocked IPs:        %12d                        ║\n", ruleStats.blockedIps));
            sb.append(String.format("║   Blocked Apps:       %12d                        ║\n", ruleStats.blockedApps));
            sb.append(String.format("║   Blocked Domains:    %12d                        ║\n", ruleStats.blockedDomains));
            sb.append(String.format("║   Blocked Ports:      %12d                        ║\n", ruleStats.blockedPorts));
        }

        sb.append("╚══════════════════════════════════════════════════════════════╝\n");
        return sb.toString();
    }

    public DPIStats getStats() {
        return stats;
    }

    public FPManager getFPManager() {
        return fpManager;
    }

    public RuleManager getRuleManager() {
        return ruleManager;
    }
}
