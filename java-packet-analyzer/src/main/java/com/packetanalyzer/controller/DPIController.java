package com.packetanalyzer.controller;

import com.packetanalyzer.config.DPIEngineConfig;
import com.packetanalyzer.flow.Connection;
import com.packetanalyzer.flow.ConnectionState;
import com.packetanalyzer.model.*;
import com.packetanalyzer.model.AnalysisResponse.*;
import com.packetanalyzer.parser.PacketParser;
import com.packetanalyzer.parser.PcapReader;
import com.packetanalyzer.rules.BlockReason;
import com.packetanalyzer.rules.RuleManager;
import com.packetanalyzer.service.DPIEngine;
import com.packetanalyzer.service.FPManager;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.io.*;
import java.nio.file.Files;
import java.text.SimpleDateFormat;
import java.util.*;

@RestController
@RequestMapping("/api")
@CrossOrigin(origins = "*")
public class DPIController {

    private final List<String> blockedIps = new ArrayList<>();
    private final List<String> blockedApps = new ArrayList<>();
    private final List<String> blockedDomains = new ArrayList<>();

    // Keep last analysis in memory for exporting
    private AnalysisResponse lastAnalysis = null;

    @PostMapping("/analyze")
    public ResponseEntity<?> analyzePcap(@RequestParam("file") MultipartFile file) {
        if (file.isEmpty()) {
            return ResponseEntity.badRequest().body("Uploaded file is empty");
        }

        File tempInput = null;
        File tempOutput = null;
        try {
            // Save uploaded file to temp path
            tempInput = File.createTempFile("upload-", ".pcap");
            file.transferTo(tempInput);

            tempOutput = File.createTempFile("filtered-", ".pcap");

            // Initialize and configure DPIEngine
            DPIEngineConfig config = new DPIEngineConfig();
            config.numLoadBalancers = 2;
            config.fpsPerLb = 2;
            
            DPIEngine engine = new DPIEngine(config);
            engine.initialize();

            // Apply active blocking rules
            for (String ip : blockedIps) engine.blockIP(ip);
            for (String app : blockedApps) engine.blockApp(app);
            for (String domain : blockedDomains) engine.blockDomain(domain);

            // Process the PCAP file through the core engine
            boolean success = engine.processFile(tempInput.getAbsolutePath(), tempOutput.getAbsolutePath());
            if (!success) {
                return ResponseEntity.status(500).body("DPI Engine failed to process the file");
            }

            // Parse detailed packet details, flows, and graphs from the processed file
            AnalysisResponse response = generateAnalysisResponse(tempInput.getAbsolutePath(), engine);
            lastAnalysis = response;

            return ResponseEntity.ok(response);

        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.status(500).body("Error analyzing PCAP: " + e.getMessage());
        } finally {
            if (tempInput != null && tempInput.exists()) tempInput.delete();
            if (tempOutput != null && tempOutput.exists()) tempOutput.delete();
        }
    }

    @PostMapping("/analyze/sample")
    public ResponseEntity<?> analyzeSample() {
        File tempInput = null;
        File tempOutput = null;
        try {
            InputStream is = getClass().getClassLoader().getResourceAsStream("test_dpi.pcap");
            if (is == null) {
                File fallbackFile = new File("samples/test_dpi.pcap");
                if (fallbackFile.exists()) {
                    is = new FileInputStream(fallbackFile);
                } else {
                    return ResponseEntity.status(404).body("Sample test_dpi.pcap not found in resources or local folder");
                }
            }

            tempInput = File.createTempFile("sample-", ".pcap");
            try (OutputStream os = new FileOutputStream(tempInput)) {
                byte[] buffer = new byte[8192];
                int bytesRead;
                while ((bytesRead = is.read(buffer)) != -1) {
                    os.write(buffer, 0, bytesRead);
                }
            }

            tempOutput = File.createTempFile("filtered-", ".pcap");

            // Initialize and configure DPIEngine
            DPIEngineConfig config = new DPIEngineConfig();
            config.numLoadBalancers = 2;
            config.fpsPerLb = 2;
            
            DPIEngine engine = new DPIEngine(config);
            engine.initialize();

            // Apply active blocking rules
            for (String ip : blockedIps) engine.blockIP(ip);
            for (String app : blockedApps) engine.blockApp(app);
            for (String domain : blockedDomains) engine.blockDomain(domain);

            // Process the PCAP file through the core engine
            boolean success = engine.processFile(tempInput.getAbsolutePath(), tempOutput.getAbsolutePath());
            if (!success) {
                return ResponseEntity.status(500).body("DPI Engine failed to process the sample file");
            }

            // Parse detailed packet details, flows, and graphs from the processed file
            AnalysisResponse response = generateAnalysisResponse(tempInput.getAbsolutePath(), engine);
            lastAnalysis = response;

            return ResponseEntity.ok(response);

        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.status(500).body("Error analyzing sample PCAP: " + e.getMessage());
        } finally {
            if (tempInput != null && tempInput.exists()) tempInput.delete();
            if (tempOutput != null && tempOutput.exists()) tempOutput.delete();
        }
    }

    @GetMapping("/rules")
    public ResponseEntity<?> getRules() {
        Map<String, List<String>> rules = new HashMap<>();
        rules.put("ips", blockedIps);
        rules.put("apps", blockedApps);
        rules.put("domains", blockedDomains);
        return ResponseEntity.ok(rules);
    }

    @PostMapping("/rules/block-ip")
    public ResponseEntity<?> blockIp(@RequestBody Map<String, String> body) {
        String ip = body.get("ip");
        if (ip != null && !ip.isEmpty() && !blockedIps.contains(ip)) {
            blockedIps.add(ip);
        }
        return ResponseEntity.ok(Map.of("message", "IP blocked successfully"));
    }

    @PostMapping("/rules/block-app")
    public ResponseEntity<?> blockApp(@RequestBody Map<String, String> body) {
        String app = body.get("app");
        if (app != null && !app.isEmpty() && !blockedApps.contains(app)) {
            blockedApps.add(app);
        }
        return ResponseEntity.ok(Map.of("message", "App blocked successfully"));
    }

    @PostMapping("/rules/block-domain")
    public ResponseEntity<?> blockDomain(@RequestBody Map<String, String> body) {
        String domain = body.get("domain");
        if (domain != null && !domain.isEmpty() && !blockedDomains.contains(domain)) {
            blockedDomains.add(domain);
        }
        return ResponseEntity.ok(Map.of("message", "Domain blocked successfully"));
    }

    @PostMapping("/rules/clear")
    public ResponseEntity<?> clearRules() {
        blockedIps.clear();
        blockedApps.clear();
        blockedDomains.clear();
        return ResponseEntity.ok(Map.of("message", "All rules cleared successfully"));
    }

    @GetMapping("/export")
    public ResponseEntity<?> exportReport(@RequestParam("format") String format) {
        if (lastAnalysis == null) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body("No analysis report available to export. Please analyze a PCAP first.");
        }

        try {
            if ("json".equalsIgnoreCase(format)) {
                return ResponseEntity.ok()
                        .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=dpi_report.json")
                        .header(HttpHeaders.CONTENT_TYPE, "application/json")
                        .body(lastAnalysis);
            } else if ("csv".equalsIgnoreCase(format)) {
                String csv = generateCSV(lastAnalysis);
                return ResponseEntity.ok()
                        .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=dpi_report.csv")
                        .header(HttpHeaders.CONTENT_TYPE, "text/csv")
                        .body(csv);
            } else if ("html".equalsIgnoreCase(format)) {
                String html = generateHTML(lastAnalysis);
                return ResponseEntity.ok()
                        .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=dpi_report.html")
                        .header(HttpHeaders.CONTENT_TYPE, "text/html")
                        .body(html);
            } else {
                return ResponseEntity.badRequest().body("Unsupported export format: " + format);
            }
        } catch (Exception e) {
            return ResponseEntity.status(500).body("Error exporting report: " + e.getMessage());
        }
    }

    // ========== Helper analysis generation logic ==========

    private AnalysisResponse generateAnalysisResponse(String pcapPath, DPIEngine engine) throws Exception {
        AnalysisResponse response = new AnalysisResponse();
        
        // 1. Gather Summary Statistics
        DPIStats engineStats = engine.getStats();
        SummaryStats stats = new SummaryStats();
        stats.totalPackets = engineStats.totalPackets.get();
        stats.totalBytes = engineStats.totalBytes.get();
        stats.tcpPackets = engineStats.tcpPackets.get();
        stats.udpPackets = engineStats.udpPackets.get();
        stats.forwardedPackets = engineStats.forwardedPackets.get();
        stats.droppedPackets = engineStats.droppedPackets.get();
        stats.dropRate = stats.totalPackets > 0 ? (100.0 * stats.droppedPackets / stats.totalPackets) : 0.0;
        stats.blockedIps = blockedIps.size();
        stats.blockedApps = blockedApps.size();
        stats.blockedDomains = blockedDomains.size();

        // 2. Parse Packet Details and track simulated block state to align with dropping decisions
        List<PacketDetail> packetDetails = new ArrayList<>();
        Map<FiveTuple, Boolean> simulatedBlockState = new HashMap<>();
        
        // Graph structures
        Map<String, GraphNode> nodeMap = new HashMap<>();
        Map<String, GraphEdge> edgeMap = new HashMap<>();

        // Timeline structures (grouped by relative seconds)
        Map<Long, TimelinePoint> timelineMap = new TreeMap<>();

        int maxPacketSize = 0;
        double firstTs = -1;
        double lastTs = 0;

        SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS");
        sdf.setTimeZone(TimeZone.getTimeZone("UTC"));

        try (PcapReader reader = new PcapReader()) {
            if (reader.open(pcapPath)) {
                RawPacket[] rawRef = new RawPacket[1];
                ParsedPacket parsed = new ParsedPacket();
                int packetId = 0;

                while (reader.readNextPacket(rawRef)) {
                    RawPacket raw = rawRef[0];
                    if (!PacketParser.parse(raw, parsed)) continue;
                    if (!parsed.isHasIp()) continue;

                    double ts = raw.getHeader().getTsSec() + (raw.getHeader().getTsUsec() / 1000000.0);
                    if (firstTs == -1) firstTs = ts;
                    lastTs = ts;

                    if (raw.getData().length > maxPacketSize) {
                        maxPacketSize = raw.getData().length;
                    }

                    int srcIpVal = RuleManager.parseIP(parsed.getSrcIp());
                    int dstIpVal = RuleManager.parseIP(parsed.getDestIp());
                    FiveTuple tuple = new FiveTuple(srcIpVal, dstIpVal, parsed.getSrcPort(), parsed.getDestPort(), parsed.getProtocol());

                    Connection conn = findConnection(tuple, engine.getFPManager());

                    // Simulation logic to mark drops
                    boolean isDropped = false;
                    boolean alreadyBlocked = simulatedBlockState.getOrDefault(tuple, false) || simulatedBlockState.getOrDefault(tuple.reverse(), false);
                    if (alreadyBlocked) {
                        isDropped = true;
                    } else {
                        Optional<BlockReason> blockReason = engine.getRuleManager().shouldBlock(
                                tuple.getSrcIp(),
                                tuple.getDstPort(),
                                conn != null ? conn.appType : AppType.UNKNOWN,
                                conn != null ? conn.sni : ""
                        );
                        if (blockReason.isPresent()) {
                            isDropped = true;
                            simulatedBlockState.put(tuple, true);
                            simulatedBlockState.put(tuple.reverse(), true);
                        }
                    }

                    // Create Packet Detail
                    PacketDetail detail = new PacketDetail();
                    detail.id = packetId++;
                    detail.timestamp = sdf.format(new Date((long) (ts * 1000)));
                    detail.timestampEpoch = ts;
                    detail.srcIp = parsed.getSrcIp();
                    detail.dstIp = parsed.getDestIp();
                    detail.protocol = PacketParser.protocolToString(parsed.getProtocol());
                    detail.srcPort = parsed.getSrcPort();
                    detail.dstPort = parsed.getDestPort();
                    detail.tcpFlags = PacketParser.tcpFlagsToString(parsed.getTcpFlags());
                    detail.length = raw.getData().length;
                    detail.ttl = parsed.getTtl();
                    detail.action = isDropped ? "DROP" : "FORWARD";

                    // Form payload summary
                    if (parsed.getPayloadLength() > 0) {
                        detail.payloadSummary = conn != null && conn.sni != null && !conn.sni.isEmpty() ? "SNI: " + conn.sni : "Payload size: " + parsed.getPayloadLength() + " bytes";
                    } else {
                        detail.payloadSummary = "No payload";
                    }

                    // Populate expandable layer details
                    List<String> layers = new ArrayList<>();
                    layers.add(String.format("Ethernet Layer: Src=%s, Dst=%s, Type=0x%04X", parsed.getSrcMac(), parsed.getDestMac(), parsed.getEtherType()));
                    layers.add(String.format("IPv4 Layer: Src=%s, Dst=%s, TTL=%d, Protocol=%d", parsed.getSrcIp(), parsed.getDestIp(), parsed.getTtl(), parsed.getProtocol()));
                    if (parsed.isHasTcp()) {
                        layers.add(String.format("TCP Layer: SrcPort=%d, DstPort=%d, Seq=%d, Ack=%d, Flags=[%s]", parsed.getSrcPort(), parsed.getDestPort(), parsed.getSeqNumber(), parsed.getAckNumber(), PacketParser.tcpFlagsToString(parsed.getTcpFlags())));
                    } else if (parsed.isHasUdp()) {
                        layers.add(String.format("UDP Layer: SrcPort=%d, DstPort=%d, Length=%d", parsed.getSrcPort(), parsed.getDestPort(), parsed.getPayloadLength() + 8));
                    }
                    detail.layerDetails = layers;
                    packetDetails.add(detail);

                    // Add to Graph Nodes and Edges
                    addGraphNode(nodeMap, parsed.getSrcIp(), "client", detail.length);
                    addGraphNode(nodeMap, parsed.getDestIp(), "server", detail.length);
                    
                    String edgeKey = parsed.getSrcIp() + "->" + parsed.getDestIp();
                    GraphEdge edge = edgeMap.get(edgeKey);
                    if (edge == null) {
                        edge = new GraphEdge();
                        edge.source = parsed.getSrcIp();
                        edge.target = parsed.getDestIp();
                        edge.protocol = detail.protocol;
                        edge.packets = 0;
                        edge.bytes = 0;
                        edgeMap.put(edgeKey, edge);
                    }
                    edge.packets++;
                    edge.bytes += detail.length;

                    // Add to timeline (bucketed by relative seconds)
                    long relativeSec = (long) (ts - firstTs);
                    TimelinePoint point = timelineMap.get(relativeSec);
                    if (point == null) {
                        point = new TimelinePoint();
                        point.timestamp = relativeSec;
                        point.timeLabel = String.format("+%ds", relativeSec);
                        point.packets = 0;
                        point.bytes = 0;
                        point.dropped = 0;
                        timelineMap.put(relativeSec, point);
                    }
                    point.packets++;
                    point.bytes += detail.length;
                    if (isDropped) point.dropped++;
                }
            }
        }

        stats.largestPacketSize = maxPacketSize;
        stats.averagePacketSize = stats.totalPackets > 0 ? ((double) stats.totalBytes / stats.totalPackets) : 0.0;
        stats.captureDuration = firstTs != -1 ? (lastTs - firstTs) : 0.0;
        stats.bandwidthBitsPerSec = stats.captureDuration > 0 ? (8.0 * stats.totalBytes / stats.captureDuration) : 0.0;

        // 3. Populate Connections (Flows)
        List<FlowDetail> flows = new ArrayList<>();
        Map<String, Long> appDistribution = new HashMap<>();
        List<DomainDetail> domains = new ArrayList<>();
        long activeConnectionsCount = 0;

        FPManager fpManager = engine.getFPManager();
        if (fpManager != null) {
            for (int i = 0; i < fpManager.getNumFPs(); i++) {
                List<Connection> trackerConns = fpManager.getFP(i).getConnectionTracker().getAllConnections();
                for (Connection conn : trackerConns) {
                    if (conn.state != ConnectionState.CLOSED && conn.state != ConnectionState.BLOCKED) {
                        activeConnectionsCount++;
                    }

                    FlowDetail flow = new FlowDetail();
                    String srcIpStr = FiveTuple.ipToString(conn.tuple.getSrcIp());
                    String dstIpStr = FiveTuple.ipToString(conn.tuple.getDstIp());
                    flow.id = srcIpStr + ":" + conn.tuple.getSrcPort() + "_" + dstIpStr + ":" + conn.tuple.getDstPort();
                    flow.client = srcIpStr;
                    flow.server = dstIpStr;
                    flow.protocol = conn.tuple.getProtocol() == 6 ? "TCP" : "UDP";
                    flow.duration = (conn.lastSeen - conn.firstSeen) / 1000.0;
                    flow.packets = conn.packetsIn + conn.packetsOut;
                    flow.bytes = conn.bytesIn + conn.bytesOut;
                    flow.application = conn.appType.getDisplayName();
                    flow.status = conn.state.name();
                    flows.add(flow);

                    appDistribution.put(conn.appType.getDisplayName(), appDistribution.getOrDefault(conn.appType.getDisplayName(), 0L) + 1);

                    // Add domains
                    if (conn.sni != null && !conn.sni.isEmpty()) {
                        DomainDetail domain = new DomainDetail();
                        domain.domain = conn.sni;
                        domain.app = conn.appType.getDisplayName();
                        domain.count = conn.packetsIn + conn.packetsOut;
                        domains.add(domain);
                        
                        // Map SNI nodes in network graph
                        addGraphNode(nodeMap, conn.sni, "domain", 0);
                        
                        String domainEdgeKey = dstIpStr + "->" + conn.sni;
                        GraphEdge dEdge = edgeMap.get(domainEdgeKey);
                        if (dEdge == null) {
                            dEdge = new GraphEdge();
                            dEdge.source = dstIpStr;
                            dEdge.target = conn.sni;
                            dEdge.protocol = "TLS/SNI";
                            dEdge.packets = conn.packetsIn;
                            dEdge.bytes = conn.bytesIn;
                            edgeMap.put(domainEdgeKey, dEdge);
                        }
                    }
                }
            }
        }
        stats.activeConnections = activeConnectionsCount;

        response.stats = stats;
        response.packets = packetDetails;
        response.flows = flows;
        response.applications = appDistribution;
        response.domains = domains;
        response.timeline = new ArrayList<>(timelineMap.values());

        GraphData graphData = new GraphData();
        graphData.nodes = new ArrayList<>(nodeMap.values());
        graphData.edges = new ArrayList<>(edgeMap.values());
        response.graph = graphData;

        return response;
    }

    private void addGraphNode(Map<String, GraphNode> nodeMap, String id, String type, long size) {
        GraphNode node = nodeMap.get(id);
        if (node == null) {
            node = new GraphNode();
            node.id = id;
            node.label = id;
            node.type = type;
            node.packets = 0;
            node.bytes = 0;
            nodeMap.put(id, node);
        }
        node.packets++;
        node.bytes += size;
    }

    private Connection findConnection(FiveTuple tuple, FPManager fpManager) {
        if (fpManager == null) return null;
        for (int i = 0; i < fpManager.getNumFPs(); i++) {
            Connection conn = fpManager.getFP(i).getConnectionTracker().getConnection(tuple);
            if (conn != null) {
                return conn;
            }
        }
        return null;
    }

    // ========== Report Exporters ==========

    private String generateCSV(AnalysisResponse report) {
        StringBuilder csv = new StringBuilder();
        csv.append("Packet ID,Timestamp,Source IP,Destination IP,Protocol,Source Port,Destination Port,Length,Action\n");
        for (PacketDetail p : report.packets) {
            csv.append(String.format("%d,%s,%s,%s,%s,%d,%d,%d,%s\n",
                    p.id, p.timestamp, p.srcIp, p.dstIp, p.protocol, p.srcPort, p.dstPort, p.length, p.action));
        }
        return csv.toString();
    }

    private String generateHTML(AnalysisResponse report) {
        StringBuilder html = new StringBuilder();
        html.append("<!DOCTYPE html><html><head><title>DPI Engine Report</title>");
        html.append("<style>body{font-family:sans-serif;background-color:#121214;color:#e1e1e6;padding:20px;}");
        html.append("table{width:100%;border-collapse:collapse;margin-top:20px;} th,td{border:1px solid #2d2d30;padding:10px;text-align:left;}");
        html.append("th{background-color:#1e1e24;}</style></head><body>");
        html.append("<h1>Deep Packet Inspection Report</h1>");
        html.append("<h3>Summary Statistics</h3>");
        html.append("<ul>");
        html.append("<li>Total Packets: ").append(report.stats.totalPackets).append("</li>");
        html.append("<li>Total Bytes: ").append(report.stats.totalBytes).append("</li>");
        html.append("<li>Forwarded: ").append(report.stats.forwardedPackets).append("</li>");
        html.append("<li>Dropped/Blocked: ").append(report.stats.droppedPackets).append("</li>");
        html.append("<li>Active Flows: ").append(report.flows.size()).append("</li>");
        html.append("</ul>");
        html.append("<h3>Recent Connections</h3>");
        html.append("<table><tr><th>Client</th><th>Server</th><th>Protocol</th><th>Duration (s)</th><th>Packets</th><th>App</th><th>Status</th></tr>");
        for (int i = 0; i < Math.min(report.flows.size(), 30); i++) {
            FlowDetail f = report.flows.get(i);
            html.append(String.format("<tr><td>%s</td><td>%s</td><td>%s</td><td>%.2f</td><td>%d</td><td>%s</td><td>%s</td></tr>",
                    f.client, f.server, f.protocol, f.duration, f.packets, f.application, f.status));
        }
        html.append("</table></body></html>");
        return html.toString();
    }
}
