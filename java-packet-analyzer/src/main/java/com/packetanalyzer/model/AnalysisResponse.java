package com.packetanalyzer.model;

import java.util.List;
import java.util.Map;

public class AnalysisResponse {
    public SummaryStats stats;
    public List<PacketDetail> packets;
    public List<FlowDetail> flows;
    public Map<String, Long> applications;
    public List<DomainDetail> domains;
    public List<TimelinePoint> timeline;
    public GraphData graph;

    public static class SummaryStats {
        public long totalPackets;
        public long totalBytes;
        public long tcpPackets;
        public long udpPackets;
        public long forwardedPackets;
        public long droppedPackets;
        public double dropRate;
        public double averagePacketSize;
        public int largestPacketSize;
        public double captureDuration; // in seconds
        public double bandwidthBitsPerSec;
        public long activeConnections;
        public int blockedIps;
        public int blockedApps;
        public int blockedDomains;
    }

    public static class PacketDetail {
        public int id;
        public String timestamp; // formatted string e.g. yyyy-MM-dd HH:mm:ss.SSSSSS
        public double timestampEpoch;
        public String srcIp;
        public String dstIp;
        public String protocol;
        public int srcPort;
        public int dstPort;
        public String tcpFlags;
        public int length;
        public int ttl;
        public String payloadSummary;
        public String action; // FORWARD, DROP
        public List<String> layerDetails;
    }

    public static class FlowDetail {
        public String id;
        public String client;
        public String server;
        public String protocol;
        public double duration; // in seconds
        public long packets;
        public long bytes;
        public String application;
        public String status; // NEW, ESTABLISHED, CLOSED, BLOCKED
    }

    public static class DomainDetail {
        public String domain;
        public String app;
        public long count;
    }

    public static class TimelinePoint {
        public double timestamp; // relative seconds from start or epoch
        public String timeLabel;
        public long packets;
        public long bytes;
        public long dropped;
    }

    public static class GraphData {
        public List<GraphNode> nodes;
        public List<GraphEdge> edges;
    }

    public static class GraphNode {
        public String id; // IP or Domain
        public String label;
        public String type; // client, server, domain
        public long packets;
        public long bytes;
    }

    public static class GraphEdge {
        public String source;
        public String target;
        public String protocol;
        public long packets;
        public long bytes;
    }
}
