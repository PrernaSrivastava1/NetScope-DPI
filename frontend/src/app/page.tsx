"use client";

import React, { useState, useEffect, useRef } from "react";
import { 
  Upload, Activity, Network, Shield, ShieldAlert, Database, 
  Search, ArrowUpDown, ChevronDown, ChevronUp, Download, 
  FileJson, FileSpreadsheet, FileCode, CheckCircle, RefreshCw, XCircle, Info, Sparkles
} from "lucide-react";
import { 
  ResponsiveContainer, AreaChart, Area, XAxis, YAxis, Tooltip, 
  PieChart, Pie, Cell, BarChart, Bar 
} from "recharts";
import { motion, AnimatePresence } from "framer-motion";

// Types corresponding to backend DTOs
interface SummaryStats {
  totalPackets: number;
  totalBytes: number;
  tcpPackets: number;
  udpPackets: number;
  forwardedPackets: number;
  droppedPackets: number;
  dropRate: number;
  averagePacketSize: number;
  largestPacketSize: number;
  captureDuration: number;
  bandwidthBitsPerSec: number;
  activeConnections: number;
  blockedIps: number;
  blockedApps: number;
  blockedDomains: number;
}

interface PacketDetail {
  id: number;
  timestamp: string;
  timestampEpoch: number;
  srcIp: string;
  dstIp: string;
  protocol: string;
  srcPort: number;
  dstPort: number;
  tcpFlags: string;
  length: number;
  ttl: number;
  payloadSummary: string;
  action: string; // FORWARD, DROP
  layerDetails: string[];
}

interface FlowDetail {
  id: string;
  client: string;
  server: string;
  protocol: string;
  duration: number;
  packets: number;
  bytes: number;
  application: string;
  status: string;
}

interface DomainDetail {
  domain: string;
  app: string;
  count: number;
}

interface TimelinePoint {
  timestamp: number;
  timeLabel: string;
  packets: number;
  bytes: number;
  dropped: number;
}

interface GraphNode {
  id: string;
  label: string;
  type: "client" | "server" | "domain";
  packets: number;
  bytes: number;
  x?: number;
  y?: number;
  vx?: number;
  vy?: number;
}

interface GraphEdge {
  source: string;
  target: string;
  protocol: string;
  packets: number;
  bytes: number;
}

interface GraphData {
  nodes: GraphNode[];
  edges: GraphEdge[];
}

interface AnalysisResponse {
  stats: SummaryStats;
  packets: PacketDetail[];
  flows: FlowDetail[];
  applications: Record<string, number>;
  domains: DomainDetail[];
  timeline: TimelinePoint[];
  graph: GraphData;
}

const COLORS = ["#00f0ff", "#10b981", "#fbbf24", "#f43f5e", "#8b5cf6", "#3b82f6", "#ec4899", "#14b8a6"];

export default function Dashboard() {
  const [file, setFile] = useState<File | null>(null);
  const [uploading, setUploading] = useState(false);
  const [progress, setProgress] = useState(0);
  const [analysis, setAnalysis] = useState<AnalysisResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<"overview" | "packets" | "flows" | "graph" | "rules" | "export">("overview");

  // Rules State
  const [rules, setRules] = useState<{ ips: string[]; apps: string[]; domains: string[] }>({ ips: [], apps: [], domains: [] });
  const [newIp, setNewIp] = useState("");
  const [newApp, setNewApp] = useState("");
  const [newDomain, setNewDomain] = useState("");

  // Search & Filter State
  const [packetSearch, setPacketSearch] = useState("");
  const [packetProtocol, setPacketProtocol] = useState("all");
  const [packetAction, setPacketAction] = useState("all");
  const [expandedPacket, setExpandedPacket] = useState<number | null>(null);

  const [flowSearch, setFlowSearch] = useState("");
  const [flowSortField, setFlowSortField] = useState<"packets" | "bytes" | "duration">("packets");
  const [flowSortOrder, setFlowSortOrder] = useState<"asc" | "desc">("desc");

  const [domainSearch, setDomainSearch] = useState("");

  // Canvas Ref for Network Graph
  const canvasRef = useRef<HTMLCanvasElement | null>(null);
  const [selectedNode, setSelectedNode] = useState<GraphNode | null>(null);

  // Load backend active rules on mount
  useEffect(() => {
    fetchRules();
  }, []);

  const fetchRules = async () => {
    try {
      const res = await fetch("http://localhost:8080/api/rules");
      if (res.ok) {
        const data = await res.json();
        setRules(data);
      }
    } catch (err) {
      console.error("Failed to load rules from backend:", err);
    }
  };

  const handleBlockAction = async (type: "ip" | "app" | "domain", value: string) => {
    if (!value.trim()) return;
    try {
      const res = await fetch(`http://localhost:8080/api/rules/block-${type}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ [type]: value })
      });
      if (res.ok) {
        if (type === "ip") setNewIp("");
        if (type === "app") setNewApp("");
        if (type === "domain") setNewDomain("");
        fetchRules();
      }
    } catch (err) {
      console.error(err);
    }
  };

  const handleClearRules = async () => {
    try {
      const res = await fetch("http://localhost:8080/api/rules/clear", { method: "POST" });
      if (res.ok) {
        fetchRules();
      }
    } catch (err) {
      console.error(err);
    }
  };

  const handleFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files[0]) {
      setFile(e.target.files[0]);
      setError(null);
    }
  };

  const triggerAnalysis = () => {
    if (!file) return;

    setUploading(true);
    setProgress(0);
    setError(null);

    const formData = new FormData();
    formData.append("file", file);

    const xhr = new XMLHttpRequest();
    xhr.open("POST", "http://localhost:8080/api/analyze");

    // Track upload progress
    xhr.upload.onprogress = (event) => {
      if (event.lengthComputable) {
        const percentage = Math.round((event.loaded / event.total) * 100);
        setProgress(percentage);
      }
    };

    xhr.onload = () => {
      setUploading(false);
      if (xhr.status === 200) {
        try {
          const result = JSON.parse(xhr.responseText) as AnalysisResponse;
          setAnalysis(result);
          setActiveTab("overview");
        } catch (e) {
          setError("Failed to parse analysis response from backend.");
        }
      } else {
        setError(xhr.responseText || "An error occurred during file analysis.");
      }
    };

    xhr.onerror = () => {
      setUploading(false);
      setError("Network error connecting to the Spring Boot backend.");
    };

    xhr.send(formData);
  };

  const triggerSampleAnalysis = () => {
    setUploading(true);
    setProgress(20);
    setError(null);

    const xhr = new XMLHttpRequest();
    xhr.open("POST", "http://localhost:8080/api/analyze/sample");

    // Mock progress loading updates for static sample
    const timer = setInterval(() => {
      setProgress((prev) => {
        if (prev >= 90) {
          clearInterval(timer);
          return 90;
        }
        return prev + 15;
      });
    }, 150);

    xhr.onload = () => {
      clearInterval(timer);
      setProgress(100);
      setTimeout(() => {
        setUploading(false);
        if (xhr.status === 200) {
          try {
            const result = JSON.parse(xhr.responseText) as AnalysisResponse;
            setAnalysis(result);
            setActiveTab("overview");
          } catch (e) {
            setError("Failed to parse sample analysis response from backend.");
          }
        } else {
          setError(xhr.responseText || "An error occurred during sample analysis.");
        }
      }, 200);
    };

    xhr.onerror = () => {
      clearInterval(timer);
      setUploading(false);
      setError("Network error connecting to the Spring Boot backend.");
    };

    xhr.send();
  };

  // Canvas Force-Directed Network Graph
  useEffect(() => {
    if (activeTab !== "graph" || !analysis || !canvasRef.current) return;

    const canvas = canvasRef.current;
    const ctx = canvas.getContext("2d");
    if (!ctx) return;

    // Reset nodes list with simulation fields
    const nodes: GraphNode[] = analysis.graph.nodes.map(n => ({
      ...n,
      x: Math.random() * canvas.width,
      y: Math.random() * canvas.height,
      vx: 0,
      vy: 0
    }));

    const edges = analysis.graph.edges;

    let animationId: number;
    let pulseAngle = 0;

    const updatePhysics = () => {
      // Repulsion between all nodes
      for (let i = 0; i < nodes.length; i++) {
        const n1 = nodes[i];
        for (let j = i + 1; j < nodes.length; j++) {
          const n2 = nodes[j];
          const dx = n2.x! - n1.x!;
          const dy = n2.y! - n1.y!;
          const dist = Math.sqrt(dx * dx + dy * dy) || 1;
          const force = 600 / (dist * dist); // Repulsion constant
          const fx = (dx / dist) * force;
          const fy = (dy / dist) * force;

          n1.vx! -= fx;
          n1.vy! -= fy;
          n2.vx! += fx;
          n2.vy! += fy;
        }

        // Gravity to center
        const cx = canvas.width / 2;
        const cy = canvas.height / 2;
        const dx = cx - n1.x!;
        const dy = cy - n1.y!;
        n1.vx! += dx * 0.004;
        n1.vy! += dy * 0.004;
      }

      // Attraction between connected nodes (edges)
      for (const edge of edges) {
        const sourceNode = nodes.find(n => n.id === edge.source);
        const targetNode = nodes.find(n => n.id === edge.target);
        if (sourceNode && targetNode) {
          const dx = targetNode.x! - sourceNode.x!;
          const dy = targetNode.y! - sourceNode.y!;
          const dist = Math.sqrt(dx * dx + dy * dy) || 1;
          const force = dist * 0.015; // Tension constant

          const fx = (dx / dist) * force;
          const fy = (dy / dist) * force;

          sourceNode.vx! += fx;
          sourceNode.vy! += fy;
          targetNode.vx! -= fx;
          targetNode.vy! -= fy;
        }
      }

      // Update positions & friction
      for (const node of nodes) {
        node.x! += node.vx!;
        node.y! += node.vy!;
        node.vx! *= 0.85; // friction
        node.vy! *= 0.85;

        // Keep inside canvas bounds
        node.x = Math.max(30, Math.min(canvas.width - 30, node.x!));
        node.y = Math.max(30, Math.min(canvas.height - 30, node.y!));
      }
    };

    const draw = () => {
      ctx.clearRect(0, 0, canvas.width, canvas.height);

      pulseAngle += 0.05;
      const pulseRadius = 1 + 0.15 * Math.sin(pulseAngle);

      // Draw edges with dynamic glow
      ctx.strokeStyle = "rgba(0, 240, 255, 0.08)";
      ctx.lineWidth = 1.5;
      for (const edge of edges) {
        const sourceNode = nodes.find(n => n.id === edge.source);
        const targetNode = nodes.find(n => n.id === edge.target);
        if (sourceNode && targetNode) {
          ctx.beginPath();
          ctx.moveTo(sourceNode.x!, sourceNode.y!);
          ctx.lineTo(targetNode.x!, targetNode.y!);
          ctx.stroke();
        }
      }

      // Draw nodes
      for (const node of nodes) {
        ctx.beginPath();
        const baseSize = node.type === "client" ? 11 : node.type === "server" ? 9 : 7;
        const size = baseSize * (selectedNode && selectedNode.id === node.id ? 1.25 : 1);
        ctx.arc(node.x!, node.y!, size, 0, 2 * Math.PI);
        
        let nodeColor = "#a855f7"; // purple for domains
        if (node.type === "client") {
          nodeColor = "#00f0ff"; // bright cyan
        } else if (node.type === "server") {
          nodeColor = "#10b981"; // emerald
        }
        
        ctx.fillStyle = nodeColor;
        ctx.fill();

        // Pulsing glow ring around selected node
        if (selectedNode && selectedNode.id === node.id) {
          ctx.beginPath();
          ctx.arc(node.x!, node.y!, size * pulseRadius, 0, 2 * Math.PI);
          ctx.strokeStyle = "rgba(255, 255, 255, 0.4)";
          ctx.lineWidth = 2;
          ctx.stroke();
        }

        // Draw shadow/glow effect
        ctx.beginPath();
        ctx.arc(node.x!, node.y!, size + 4, 0, 2 * Math.PI);
        ctx.strokeStyle = nodeColor + "1a"; // 10% opacity
        ctx.lineWidth = 4;
        ctx.stroke();

        // Node label
        ctx.fillStyle = "#f8fafc";
        ctx.font = "bold 10px monospace";
        ctx.textAlign = "center";
        ctx.fillText(node.label, node.x!, node.y! - size - 6);
      }
    };

    const tick = () => {
      updatePhysics();
      draw();
      animationId = requestAnimationFrame(tick);
    };

    tick();

    // Canvas click handler
    const handleCanvasClick = (e: MouseEvent) => {
      const rect = canvas.getBoundingClientRect();
      const mouseX = e.clientX - rect.left;
      const mouseY = e.clientY - rect.top;

      let foundNode = false;
      for (const node of nodes) {
        const dx = node.x! - mouseX;
        const dy = node.y! - mouseY;
        const dist = Math.sqrt(dx * dx + dy * dy);
        if (dist < 18) {
          setSelectedNode(node);
          foundNode = true;
          break;
        }
      }
      if (!foundNode) setSelectedNode(null);
    };

    canvas.addEventListener("click", handleCanvasClick);

    return () => {
      cancelAnimationFrame(animationId);
      canvas.removeEventListener("click", handleCanvasClick);
    };
  }, [activeTab, analysis, selectedNode]);

  // Packets Table Filtering
  const filteredPackets = analysis?.packets.filter(p => {
    const matchesSearch = p.srcIp.includes(packetSearch) || p.dstIp.includes(packetSearch) || p.payloadSummary.toLowerCase().includes(packetSearch.toLowerCase());
    const matchesProtocol = packetProtocol === "all" || p.protocol.toLowerCase() === packetProtocol.toLowerCase();
    const matchesAction = packetAction === "all" || p.action === packetAction;
    return matchesSearch && matchesProtocol && matchesAction;
  }) || [];

  // Flows Filtering & Sorting
  const filteredFlows = analysis?.flows.filter(f => {
    return f.client.includes(flowSearch) || f.server.includes(flowSearch) || f.application.toLowerCase().includes(flowSearch.toLowerCase());
  }).sort((a, b) => {
    let aVal = a[flowSortField];
    let bVal = b[flowSortField];
    if (flowSortOrder === "asc") {
      return aVal > bVal ? 1 : -1;
    } else {
      return aVal < bVal ? 1 : -1;
    }
  }) || [];

  // Domain Filter
  const filteredDomains = analysis?.domains.filter(d => d.domain.toLowerCase().includes(domainSearch.toLowerCase())) || [];

  // Format charts data
  const appPieData = analysis ? Object.entries(analysis.applications).map(([name, count]) => ({ name, value: count })) : [];
  const protocolData = analysis ? [
    { name: "TCP", value: analysis.stats.tcpPackets },
    { name: "UDP", value: analysis.stats.udpPackets },
    { name: "DNS", value: analysis.packets.filter(p => p.srcPort === 53 || p.dstPort === 53).length },
    { name: "TLS", value: analysis.packets.filter(p => p.srcPort === 443 || p.dstPort === 443).length }
  ] : [];

  return (
    <div className="min-h-screen bg-[#07080d] text-slate-100 font-sans selection:bg-cyan-500 selection:text-black relative overflow-hidden">
      
      {/* Radiant Background Glows */}
      <div className="absolute top-0 left-1/4 w-[500px] h-[500px] bg-cyan-500/5 rounded-full blur-[120px] pointer-events-none" />
      <div className="absolute bottom-0 right-1/4 w-[600px] h-[600px] bg-violet-600/5 rounded-full blur-[140px] pointer-events-none" />

      {/* Top Header */}
      <header className="border-b border-slate-900/60 bg-[#080a10]/80 backdrop-blur-xl sticky top-0 z-50 px-6 py-4 flex items-center justify-between shadow-lg shadow-black/10">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-gradient-to-tr from-cyan-400 to-indigo-500 flex items-center justify-center shadow-lg shadow-cyan-400/25 relative overflow-hidden group">
            <div className="absolute inset-0 bg-white/20 opacity-0 group-hover:opacity-100 transition-opacity" />
            <Activity className="w-5 h-5 text-black" />
          </div>
          <div>
            <h1 className="text-xl font-extrabold tracking-tight bg-gradient-to-r from-cyan-400 via-teal-400 to-indigo-400 bg-clip-text text-transparent flex items-center gap-1">
              DPI Net-Scope <Sparkles className="w-4 h-4 text-cyan-400" />
            </h1>
            <p className="text-[10px] text-slate-500 font-bold uppercase tracking-widest">Enterprise DPI Visualization</p>
          </div>
        </div>

        {analysis && (
          <div className="flex items-center gap-1.5 border border-slate-900/80 rounded-xl p-1 bg-slate-950/80 backdrop-blur-md">
            {(["overview", "packets", "flows", "graph", "rules", "export"] as const).map((tab) => (
              <button
                key={tab}
                onClick={() => setActiveTab(tab)}
                className={`px-4 py-2 text-xs font-bold uppercase tracking-wider rounded-lg transition-all duration-300 relative ${
                  activeTab === tab 
                    ? "bg-cyan-500/10 text-cyan-400 border border-cyan-500/20 shadow-sm" 
                    : "text-slate-400 hover:text-slate-200 hover:bg-slate-900/30 border border-transparent"
                }`}
              >
                {tab}
              </button>
            ))}
          </div>
        )}
      </header>

      {/* Main Content Area */}
      <main className="max-w-7xl mx-auto p-6 relative z-10">
        <AnimatePresence mode="wait">
          
          {/* UPLOAD CENTER / LANDING PAGE */}
          {!analysis && (
            <motion.div 
              initial={{ opacity: 0, y: 30 }} 
              animate={{ opacity: 1, y: 0 }} 
              exit={{ opacity: 0, y: -30 }}
              transition={{ duration: 0.4 }}
              className="py-16 flex flex-col items-center justify-center max-w-xl mx-auto text-center"
            >
              <div className="w-20 h-20 rounded-2xl bg-gradient-to-br from-cyan-950/30 to-slate-950/30 border border-cyan-800/40 flex items-center justify-center mb-8 shadow-2xl shadow-cyan-500/5 relative overflow-hidden group">
                <div className="absolute inset-0 bg-cyan-500/5 blur-xl group-hover:scale-150 transition-transform" />
                <Network className="w-10 h-10 text-cyan-400" />
              </div>
              <h2 className="text-4xl font-black tracking-tight mb-4 bg-gradient-to-r from-slate-50 via-slate-100 to-slate-400 bg-clip-text text-transparent">
                Deep Packet Inspection System
              </h2>
              <p className="text-slate-400 text-sm mb-10 leading-relaxed font-medium">
                Upload raw PCAP capture logs to execute stateful deep network tracking, protocol extraction, and custom firewall analysis configurations.
              </p>

              {/* Upload Drop Zone */}
              <div className="w-full bg-[#0a0d14]/40 border border-slate-900 backdrop-blur-md hover:border-cyan-500/30 rounded-3xl p-12 transition-all duration-300 group flex flex-col items-center justify-center shadow-2xl shadow-black/20 relative overflow-hidden">
                <div className="absolute top-0 left-0 w-full h-[1px] bg-gradient-to-r from-transparent via-cyan-500/10 to-transparent" />
                <input 
                  type="file" 
                  accept=".pcap" 
                  onChange={handleFileUpload} 
                  className="hidden" 
                  id="pcap-uploader"
                  disabled={uploading}
                />
                <label 
                  htmlFor="pcap-uploader" 
                  className="cursor-pointer flex flex-col items-center gap-4 w-full"
                >
                  <div className="w-14 h-14 rounded-2xl bg-slate-950/80 flex items-center justify-center border border-slate-900 group-hover:border-cyan-500/20 group-hover:bg-slate-900/50 transition-all shadow-inner">
                    <Upload className="w-6 h-6 text-slate-400 group-hover:text-cyan-400" />
                  </div>
                  <span className="text-sm font-bold text-slate-200">
                    {file ? file.name : "Select raw PCAP file"}
                  </span>
                  <span className="text-xs text-slate-500 font-medium tracking-wide">
                    Standard PCAP formats supported
                  </span>
                </label>

                {file && !uploading && (
                  <button 
                    onClick={triggerAnalysis}
                    className="mt-8 w-full py-3.5 rounded-xl bg-gradient-to-r from-cyan-400 to-indigo-500 hover:from-cyan-300 hover:to-indigo-400 text-black font-extrabold text-xs uppercase tracking-wider shadow-lg shadow-cyan-400/25 active:scale-95 transition-all duration-300"
                  >
                    Start DPI Inspection
                  </button>
                )}

                {!file && !uploading && (
                  <button 
                    onClick={triggerSampleAnalysis}
                    className="mt-8 px-6 py-2.5 rounded-xl border border-slate-800 hover:border-slate-700 hover:bg-slate-900/10 text-cyan-400 font-bold text-xs uppercase tracking-wider transition-colors active:scale-95 flex items-center gap-1.5"
                  >
                    Or Load Sample PCAP
                  </button>
                )}

                {uploading && (
                  <div className="w-full mt-8">
                    <div className="flex justify-between text-[11px] font-bold text-slate-400 mb-2">
                      <span>RUNNING DEEP INSPECTION ENGINE...</span>
                      <span>{progress}%</span>
                    </div>
                    <div className="w-full h-2 bg-slate-950 rounded-full overflow-hidden p-[1px] border border-slate-900">
                      <div 
                        className="h-full bg-gradient-to-r from-cyan-400 to-indigo-500 rounded-full transition-all duration-300"
                        style={{ width: `${progress}%` }}
                      />
                    </div>
                  </div>
                )}
              </div>

              {/* Core Features & Value Proposal */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mt-12 w-full text-left">
                <div className="bg-[#0b0e14]/40 border border-slate-900/60 p-5 rounded-2xl relative overflow-hidden group shadow-lg shadow-black/5 before:absolute before:top-0 before:left-0 before:w-full before:h-[1px] before:bg-gradient-to-r before:from-transparent before:via-cyan-400/20 before:to-transparent">
                  <h4 className="text-xs font-bold uppercase tracking-wider text-slate-300 flex items-center gap-2">
                    <Activity className="w-4 h-4 text-cyan-400" /> Parallel Flow Balancing
                  </h4>
                  <p className="text-[11px] text-slate-400 mt-2 leading-relaxed font-medium">
                    Uses consistent hashing on packet IP/port tuples to dispatch frames to dedicated queues, solving multi-threaded ordering issues.
                  </p>
                </div>

                <div className="bg-[#0b0e14]/40 border border-slate-900/60 p-5 rounded-2xl relative overflow-hidden group shadow-lg shadow-black/5 before:absolute before:top-0 before:left-0 before:w-full before:h-[1px] before:bg-gradient-to-r before:from-transparent before:via-cyan-400/20 before:to-transparent">
                  <h4 className="text-xs font-bold uppercase tracking-wider text-slate-300 flex items-center gap-2">
                    <Network className="w-4 h-4 text-cyan-400" /> Deep Traffic Profiling
                  </h4>
                  <p className="text-[11px] text-slate-400 mt-2 leading-relaxed font-medium">
                    Mines client handshakes to extract TLS Server Name Indications (SNI), DNS lookups, and HTTP headers for instant app identification.
                  </p>
                </div>

                <div className="bg-[#0b0e14]/40 border border-slate-900/60 p-5 rounded-2xl relative overflow-hidden group shadow-lg shadow-black/5 before:absolute before:top-0 before:left-0 before:w-full before:h-[1px] before:bg-gradient-to-r before:from-transparent before:via-cyan-400/20 before:to-transparent">
                  <h4 className="text-xs font-bold uppercase tracking-wider text-slate-300 flex items-center gap-2">
                    <Shield className="w-4 h-4 text-cyan-400" /> Firewall Rule Simulator
                  </h4>
                  <p className="text-[11px] text-slate-400 mt-2 leading-relaxed font-medium">
                    Apply live block rules for specific IPs, domains, or app signatures to simulate drop profiles without changing code.
                  </p>
                </div>

                <div className="bg-[#0b0e14]/40 border border-slate-900/60 p-5 rounded-2xl relative overflow-hidden group shadow-lg shadow-black/5 before:absolute before:top-0 before:left-0 before:w-full before:h-[1px] before:bg-gradient-to-r before:from-transparent before:via-cyan-400/20 before:to-transparent">
                  <h4 className="text-xs font-bold uppercase tracking-wider text-slate-300 flex items-center gap-2">
                    <Database className="w-4 h-4 text-cyan-400" /> Topological Graphs
                  </h4>
                  <p className="text-[11px] text-slate-400 mt-2 leading-relaxed font-medium">
                    Transforms raw packets into an interactive, force-directed node map. Inspect device bandwidth, connection counts, and protocols.
                  </p>
                </div>
              </div>

              {error && (
                <div className="mt-8 p-4 rounded-2xl bg-rose-950/10 border border-rose-800/20 flex items-start gap-3 text-left">
                  <XCircle className="w-5 h-5 text-rose-400 shrink-0 mt-0.5" />
                  <div>
                    <h4 className="text-xs font-bold text-rose-300 uppercase tracking-wide">System Exception</h4>
                    <p className="text-xs text-rose-400/80 mt-1 leading-normal font-medium">{error}</p>
                  </div>
                </div>
              )}
            </motion.div>
          )}

          {/* ANALYSIS VISUALIZATION DASHBOARD */}
          {analysis && (
            <motion.div
              key={activeTab}
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -20 }}
              transition={{ duration: 0.3 }}
              className="space-y-6"
            >
              
              {/* TAB 1: OVERVIEW */}
              {activeTab === "overview" && (
                <>
                  {/* Summary Metric Cards */}
                  <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
                    <div className="bg-[#0b0e14]/40 border border-slate-900/80 backdrop-blur rounded-2xl p-5 relative overflow-hidden group shadow-lg shadow-black/5 before:absolute before:top-0 before:left-0 before:w-full before:h-[1px] before:bg-gradient-to-r before:from-transparent before:via-cyan-400/20 before:to-transparent">
                      <div className="absolute right-0 bottom-0 w-24 h-24 bg-cyan-500/5 rounded-full blur-2xl group-hover:scale-125 transition-transform" />
                      <span className="text-[10px] font-bold text-slate-500 uppercase tracking-widest block">Total Packets</span>
                      <h3 className="text-3xl font-extrabold text-cyan-400 mt-2 tracking-tight">{analysis.stats.totalPackets.toLocaleString()}</h3>
                      <p className="text-xs text-slate-500 mt-1.5 font-medium">Parsed from Capture</p>
                    </div>

                    <div className="bg-[#0b0e14]/40 border border-slate-900/80 backdrop-blur rounded-2xl p-5 relative overflow-hidden group shadow-lg shadow-black/5 before:absolute before:top-0 before:left-0 before:w-full before:h-[1px] before:bg-gradient-to-r before:from-transparent before:via-emerald-400/20 before:to-transparent">
                      <div className="absolute right-0 bottom-0 w-24 h-24 bg-emerald-500/5 rounded-full blur-2xl group-hover:scale-125 transition-transform" />
                      <span className="text-[10px] font-bold text-slate-500 uppercase tracking-widest block">Forwarded</span>
                      <h3 className="text-3xl font-extrabold text-emerald-400 mt-2 tracking-tight">{analysis.stats.forwardedPackets.toLocaleString()}</h3>
                      <p className="text-xs text-slate-500 mt-1.5 font-medium">{((analysis.stats.forwardedPackets / analysis.stats.totalPackets) * 100).toFixed(1)}% Forward Rate</p>
                    </div>

                    <div className="bg-[#0b0e14]/40 border border-slate-900/80 backdrop-blur rounded-2xl p-5 relative overflow-hidden group shadow-lg shadow-black/5 before:absolute before:top-0 before:left-0 before:w-full before:h-[1px] before:bg-gradient-to-r before:from-transparent before:via-rose-400/20 before:to-transparent">
                      <div className="absolute right-0 bottom-0 w-24 h-24 bg-rose-500/5 rounded-full blur-2xl group-hover:scale-125 transition-transform" />
                      <span className="text-[10px] font-bold text-slate-500 uppercase tracking-widest block">Blocked / Dropped</span>
                      <h3 className="text-3xl font-extrabold text-rose-400 mt-2 tracking-tight">{analysis.stats.droppedPackets.toLocaleString()}</h3>
                      <p className="text-xs text-slate-500 mt-1.5 font-medium">{analysis.stats.dropRate.toFixed(2)}% Dropped Rate</p>
                    </div>

                    <div className="bg-[#0b0e14]/40 border border-slate-900/80 backdrop-blur rounded-2xl p-5 relative overflow-hidden group shadow-lg shadow-black/5 before:absolute before:top-0 before:left-0 before:w-full before:h-[1px] before:bg-gradient-to-r before:from-transparent before:via-purple-400/20 before:to-transparent">
                      <div className="absolute right-0 bottom-0 w-24 h-24 bg-purple-500/5 rounded-full blur-2xl group-hover:scale-125 transition-transform" />
                      <span className="text-[10px] font-bold text-slate-500 uppercase tracking-widest block">Active Connections</span>
                      <h3 className="text-3xl font-extrabold text-purple-400 mt-2 tracking-tight">{analysis.stats.activeConnections.toLocaleString()}</h3>
                      <p className="text-xs text-slate-500 mt-1.5 font-medium">Stateful Flow tracker</p>
                    </div>
                  </div>

                  {/* Charts Grid */}
                  <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                    
                    {/* Timeline */}
                    <div className="bg-[#0b0e14]/40 border border-slate-900/80 backdrop-blur rounded-3xl p-6 md:col-span-2 space-y-4 shadow-lg before:absolute before:top-0 before:left-0 before:w-full before:h-[1px] before:bg-gradient-to-r before:from-transparent before:via-slate-500/10 before:to-transparent">
                      <div className="flex justify-between items-center">
                        <h4 className="text-xs font-bold uppercase tracking-wider text-slate-400">Network Activity Timeline</h4>
                        <span className="text-[10px] bg-slate-950 text-slate-500 px-2.5 py-1 rounded-lg border border-slate-900/80 font-bold uppercase">Bucketed (Seconds)</span>
                      </div>
                      <div className="h-64">
                        <ResponsiveContainer width="100%" height="100%">
                          <AreaChart data={analysis.timeline}>
                            <defs>
                              <linearGradient id="colorPackets" x1="0" y1="0" x2="0" y2="1">
                                <stop offset="5%" stopColor="#00f0ff" stopOpacity={0.25}/>
                                <stop offset="95%" stopColor="#00f0ff" stopOpacity={0}/>
                              </linearGradient>
                            </defs>
                            <XAxis dataKey="timeLabel" stroke="#334155" fontSize={10} tickLine={false} axisLine={false} />
                            <YAxis stroke="#334155" fontSize={10} tickLine={false} axisLine={false} />
                            <Tooltip contentStyle={{ backgroundColor: "#080a10", borderColor: "#1e293b", color: "#f1f5f9", borderRadius: "12px", border: "1px solid #1e293b" }} />
                            <Area type="monotone" dataKey="packets" name="Packets/s" stroke="#00f0ff" strokeWidth={2} fillOpacity={1} fill="url(#colorPackets)" />
                          </AreaChart>
                        </ResponsiveContainer>
                      </div>
                    </div>

                    {/* App Distribution Pie */}
                    <div className="bg-[#0b0e14]/40 border border-slate-900/80 backdrop-blur rounded-3xl p-6 space-y-4 shadow-lg before:absolute before:top-0 before:left-0 before:w-full before:h-[1px] before:bg-gradient-to-r before:from-transparent before:via-slate-500/10 before:to-transparent">
                      <h4 className="text-xs font-bold uppercase tracking-wider text-slate-400">Detected Applications</h4>
                      <div className="h-60 flex items-center justify-center relative">
                        <ResponsiveContainer width="100%" height="100%">
                          <PieChart>
                            <Pie
                              data={appPieData}
                              cx="50%"
                              cy="50%"
                              innerRadius={65}
                              outerRadius={85}
                              paddingAngle={5}
                              dataKey="value"
                            >
                              {appPieData.map((entry, index) => (
                                <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                              ))}
                            </Pie>
                            <Tooltip contentStyle={{ backgroundColor: "#080a10", borderColor: "#1e293b", color: "#f1f5f9", borderRadius: "12px", border: "1px solid #1e293b" }} />
                          </PieChart>
                        </ResponsiveContainer>
                        <div className="absolute text-center">
                          <span className="text-[10px] text-slate-500 font-bold block uppercase tracking-wider">Total Flows</span>
                          <span className="text-2xl font-black text-slate-100">{analysis.flows.length}</span>
                        </div>
                      </div>
                      <div className="flex flex-wrap gap-x-4 gap-y-2 justify-center max-h-16 overflow-y-auto custom-scroll">
                        {appPieData.map((entry, idx) => (
                          <div key={idx} className="flex items-center gap-1.5 text-[11px] font-semibold text-slate-400">
                            <div className="w-2.5 h-2.5 rounded-full" style={{ backgroundColor: COLORS[idx % COLORS.length] }} />
                            <span>{entry.name} ({entry.value})</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  </div>

                  {/* Bottom Grid: Protocol Bar Chart + Domain Table */}
                  <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                    
                    {/* Protocol Bar Chart */}
                    <div className="bg-[#0b0e14]/40 border border-slate-900/80 backdrop-blur rounded-3xl p-6 space-y-4 shadow-lg before:absolute before:top-0 before:left-0 before:w-full before:h-[1px] before:bg-gradient-to-r before:from-transparent before:via-slate-500/10 before:to-transparent">
                      <h4 className="text-xs font-bold uppercase tracking-wider text-slate-400">Protocol Breakdown</h4>
                      <div className="h-64">
                        <ResponsiveContainer width="100%" height="100%">
                          <BarChart data={protocolData}>
                            <XAxis dataKey="name" stroke="#334155" fontSize={10} tickLine={false} axisLine={false} />
                            <YAxis stroke="#334155" fontSize={10} tickLine={false} axisLine={false} />
                            <Tooltip contentStyle={{ backgroundColor: "#080a10", borderColor: "#1e293b", color: "#f1f5f9", borderRadius: "12px", border: "1px solid #1e293b" }} />
                            <Bar dataKey="value" name="Packets" fill="#00f0ff" radius={[4, 4, 0, 0]}>
                              {protocolData.map((entry, index) => (
                                <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                              ))}
                            </Bar>
                          </BarChart>
                        </ResponsiveContainer>
                      </div>
                    </div>

                    {/* Domain Table */}
                    <div className="bg-[#0b0e14]/40 border border-slate-900/80 backdrop-blur rounded-3xl p-6 md:col-span-2 space-y-4 flex flex-col shadow-lg before:absolute before:top-0 before:left-0 before:w-full before:h-[1px] before:bg-gradient-to-r before:from-transparent before:via-slate-500/10 before:to-transparent">
                      <div className="flex justify-between items-center">
                        <h4 className="text-xs font-bold uppercase tracking-wider text-slate-400">Domain / SNI Explorer</h4>
                        <div className="relative w-48">
                          <Search className="w-3.5 h-3.5 text-slate-500 absolute left-3 top-1/2 -translate-y-1/2" />
                          <input 
                            type="text" 
                            placeholder="Search SNI..."
                            value={domainSearch}
                            onChange={(e) => setDomainSearch(e.target.value)}
                            className="w-full bg-slate-950/80 text-xs rounded-lg pl-9 pr-3 py-1.5 border border-slate-900 focus:border-cyan-500/20 focus:outline-none"
                          />
                        </div>
                      </div>
                      <div className="overflow-x-auto grow custom-scroll">
                        <table className="w-full text-xs text-left">
                          <thead>
                            <tr className="border-b border-slate-900/60 text-slate-400 uppercase tracking-widest font-bold">
                              <th className="py-3">Domain name / SNI</th>
                              <th className="py-3">Associated Application</th>
                              <th className="py-3 text-right">Packets count</th>
                            </tr>
                          </thead>
                          <tbody>
                            {filteredDomains.slice(0, 5).map((dom, idx) => (
                              <tr key={idx} className="border-b border-slate-900/20 hover:bg-slate-900/10 transition-colors">
                                <td className="py-3.5 font-bold text-slate-200 font-mono">{dom.domain}</td>
                                <td className="py-3.5 text-cyan-400 font-semibold">{dom.app}</td>
                                <td className="py-3.5 text-right text-slate-400 font-bold">{dom.count}</td>
                              </tr>
                            ))}
                            {filteredDomains.length === 0 && (
                              <tr>
                                <td colSpan={3} className="text-center py-8 text-slate-500 font-bold">No domains detected matching query</td>
                              </tr>
                            )}
                          </tbody>
                        </table>
                      </div>
                    </div>

                  </div>
                </>
              )}

              {/* TAB 2: PACKET EXPLORER */}
              {activeTab === "packets" && (
                <div className="bg-[#0b0e14]/40 border border-slate-900/80 backdrop-blur rounded-3xl p-6 space-y-4 shadow-lg before:absolute before:top-0 before:left-0 before:w-full before:h-[1px] before:bg-gradient-to-r before:from-transparent before:via-slate-500/10 before:to-transparent">
                  <div className="flex flex-wrap gap-4 items-center justify-between">
                    <h3 className="text-xs font-bold uppercase tracking-wider text-slate-400">Parsed Packet Log</h3>
                    
                    {/* Search & Filters */}
                    <div className="flex flex-wrap gap-2 items-center">
                      <div className="relative w-64">
                        <Search className="w-3.5 h-3.5 text-slate-500 absolute left-3 top-1/2 -translate-y-1/2" />
                        <input 
                          type="text" 
                          placeholder="Search IP or payload..."
                          value={packetSearch}
                          onChange={(e) => setPacketSearch(e.target.value)}
                          className="w-full bg-slate-950/80 text-xs rounded-lg pl-9 pr-3 py-2.5 border border-slate-900 focus:border-cyan-500/20 focus:outline-none"
                        />
                      </div>

                      <select 
                        value={packetProtocol} 
                        onChange={(e) => setPacketProtocol(e.target.value)}
                        className="bg-slate-950/80 text-xs rounded-lg px-3 py-2.5 border border-slate-900 focus:border-cyan-500/20 focus:outline-none font-bold text-slate-300"
                      >
                        <option value="all">All Protocols</option>
                        <option value="tcp">TCP</option>
                        <option value="udp">UDP</option>
                      </select>

                      <select 
                        value={packetAction} 
                        onChange={(e) => setPacketAction(e.target.value)}
                        className="bg-slate-950/80 text-xs rounded-lg px-3 py-2.5 border border-slate-900 focus:border-cyan-500/20 focus:outline-none font-bold text-slate-300"
                      >
                        <option value="all">All Actions</option>
                        <option value="FORWARD">Forwarded</option>
                        <option value="DROP">Dropped / Blocked</option>
                      </select>
                    </div>
                  </div>

                  {/* Packet Details Table */}
                  <div className="overflow-x-auto max-h-[500px] overflow-y-auto custom-scroll">
                    <table className="w-full text-xs text-left">
                      <thead>
                        <tr className="border-b border-slate-900/60 text-slate-500 uppercase tracking-widest font-bold sticky top-0 bg-[#080a10] z-10 py-3">
                          <th className="py-3 px-2 w-12">No.</th>
                          <th className="py-3 px-2">Timestamp</th>
                          <th className="py-3 px-2">Source IP</th>
                          <th className="py-3 px-2">Destination IP</th>
                          <th className="py-3 px-2">Protocol</th>
                          <th className="py-3 px-2">Flags</th>
                          <th className="py-3 px-2 text-right">Size</th>
                          <th className="py-3 px-2 text-center">Action</th>
                          <th className="py-3 px-2">Payload Summary</th>
                          <th className="py-3 px-2 w-10"></th>
                        </tr>
                      </thead>
                      <tbody>
                        {filteredPackets.slice(0, 100).map((pkt) => (
                          <React.Fragment key={pkt.id}>
                            <tr 
                              onClick={() => setExpandedPacket(expandedPacket === pkt.id ? null : pkt.id)}
                              className="border-b border-slate-900/20 hover:bg-slate-900/10 cursor-pointer transition-colors"
                            >
                              <td className="py-4 px-2 font-bold text-slate-500">{pkt.id}</td>
                              <td className="py-4 px-2 text-slate-400 font-mono">{pkt.timestamp.split(" ")[1]}</td>
                              <td className="py-4 px-2 font-bold text-slate-300 font-mono">{pkt.srcIp}</td>
                              <td className="py-4 px-2 font-bold text-slate-300 font-mono">{pkt.dstIp}</td>
                              <td className="py-4 px-2 text-cyan-400 font-extrabold">{pkt.protocol}</td>
                              <td className="py-4 px-2 text-slate-400 font-mono">{pkt.tcpFlags || "none"}</td>
                              <td className="py-4 px-2 text-right text-slate-400 font-bold font-mono">{pkt.length}</td>
                              <td className="py-4 px-2 text-center">
                                <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                                  pkt.action === "FORWARD" 
                                    ? "bg-emerald-950/20 text-emerald-400 border border-emerald-900/20" 
                                    : "bg-rose-950/20 text-rose-400 border border-rose-900/20"
                                }`}>
                                  {pkt.action}
                                </span>
                              </td>
                              <td className="py-4 px-2 text-slate-400 max-w-[200px] truncate">{pkt.payloadSummary}</td>
                              <td className="py-4 px-2 text-slate-500">
                                {expandedPacket === pkt.id ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
                              </td>
                            </tr>
                            
                            {/* Expandable Layer Details */}
                            {expandedPacket === pkt.id && (
                              <tr>
                                <td colSpan={10} className="bg-slate-950/60 p-5 border-b border-slate-900/40">
                                  <div className="space-y-2">
                                    <h4 className="text-[10px] font-extrabold uppercase tracking-widest text-slate-500 mb-1 flex items-center gap-1">
                                      <Database className="w-3.5 h-3.5" /> Decoded Packet Headers
                                    </h4>
                                    {pkt.layerDetails.map((layer, lIdx) => (
                                      <div 
                                        key={lIdx}
                                        className="py-2.5 px-4 bg-slate-950 border border-slate-900/80 rounded-xl text-slate-300 font-mono text-[11px] flex justify-between shadow-inner"
                                      >
                                        <span>{layer}</span>
                                        {lIdx === 1 && <span className="text-[10px] text-slate-500 font-bold">TTL: {pkt.ttl}</span>}
                                      </div>
                                    ))}
                                  </div>
                                </td>
                              </tr>
                            )}
                          </React.Fragment>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              )}

              {/* TAB 3: FLOW EXPLORER */}
              {activeTab === "flows" && (
                <div className="bg-[#0b0e14]/40 border border-slate-900/80 backdrop-blur rounded-3xl p-6 space-y-4 shadow-lg before:absolute before:top-0 before:left-0 before:w-full before:h-[1px] before:bg-gradient-to-r before:from-transparent before:via-slate-500/10 before:to-transparent">
                  <div className="flex flex-wrap gap-4 items-center justify-between">
                    <h3 className="text-xs font-bold uppercase tracking-wider text-slate-400">Flow Conversations</h3>
                    
                    {/* Search & Sort */}
                    <div className="flex flex-wrap gap-2 items-center">
                      <div className="relative w-64">
                        <Search className="w-3.5 h-3.5 text-slate-500 absolute left-3 top-1/2 -translate-y-1/2" />
                        <input 
                          type="text" 
                          placeholder="Search flows..."
                          value={flowSearch}
                          onChange={(e) => setFlowSearch(e.target.value)}
                          className="w-full bg-slate-950/80 text-xs rounded-lg pl-9 pr-3 py-2.5 border border-slate-900 focus:border-cyan-500/20 focus:outline-none"
                        />
                      </div>

                      <select 
                        value={flowSortField} 
                        onChange={(e) => setFlowSortField(e.target.value as any)}
                        className="bg-slate-950/80 text-xs rounded-lg px-3 py-2.5 border border-slate-900 focus:border-cyan-500/20 focus:outline-none font-bold text-slate-300"
                      >
                        <option value="packets">Packets count</option>
                        <option value="bytes">Byte size</option>
                        <option value="duration">Flow duration</option>
                      </select>

                      <button
                        onClick={() => setFlowSortOrder(flowSortOrder === "asc" ? "desc" : "asc")}
                        className="p-2.5 bg-slate-950/80 hover:bg-slate-900 border border-slate-900 rounded-lg text-slate-400 hover:text-slate-200 transition-colors"
                      >
                        <ArrowUpDown className="w-4 h-4" />
                      </button>
                    </div>
                  </div>

                  {/* Flow list */}
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4 max-h-[500px] overflow-y-auto pr-2 custom-scroll">
                    {filteredFlows.map((flow, idx) => (
                      <div 
                        key={idx}
                        className="bg-[#0c0f17]/40 border border-slate-900/60 rounded-2xl p-4 flex flex-col justify-between hover:border-slate-800 hover:bg-slate-900/10 transition-all duration-300 relative overflow-hidden before:absolute before:top-0 before:left-0 before:w-1 before:h-full before:bg-gradient-to-b before:from-cyan-400/30 before:to-transparent"
                      >
                        <div className="flex justify-between items-start mb-4">
                          <div className="flex items-center gap-1.5">
                            <span className="text-[10px] font-bold bg-slate-950 border border-slate-900 text-slate-400 px-2.5 py-0.5 rounded-lg">
                              {flow.protocol}
                            </span>
                            <span className={`text-[10px] font-bold px-2.5 py-0.5 rounded-lg ${
                              flow.status === "BLOCKED" 
                                ? "bg-rose-950/20 text-rose-400 border border-rose-900/20" 
                                : "bg-cyan-950/20 text-cyan-400 border border-cyan-900/20"
                            }`}>
                              {flow.status}
                            </span>
                          </div>
                          <span className="text-xs font-bold text-cyan-400">{flow.application}</span>
                        </div>

                        {/* Connection Visual */}
                        <div className="flex items-center justify-between mb-4 bg-slate-950/60 rounded-xl p-3 border border-slate-900/60">
                          <div className="text-left">
                            <span className="text-[9px] text-slate-500 block uppercase tracking-wider font-bold">Client IP</span>
                            <span className="text-xs font-bold text-slate-300 font-mono">{flow.client}</span>
                          </div>
                          <div className="w-16 h-[1px] bg-gradient-to-r from-transparent via-cyan-500/30 to-transparent relative">
                            <div className="absolute right-0 top-1/2 -translate-y-1/2 w-1.5 h-1.5 rounded-full bg-cyan-400 shadow-lg shadow-cyan-400/50" />
                          </div>
                          <div className="text-right">
                            <span className="text-[9px] text-slate-500 block uppercase tracking-wider font-bold">Server IP</span>
                            <span className="text-xs font-bold text-slate-300 font-mono">{flow.server}</span>
                          </div>
                        </div>

                        {/* Traffic Details */}
                        <div className="grid grid-cols-3 gap-2 text-xs border-t border-slate-900/40 pt-3">
                          <div>
                            <span className="text-[9px] text-slate-500 block uppercase font-bold">Packets</span>
                            <span className="font-bold text-slate-300 font-mono">{flow.packets}</span>
                          </div>
                          <div>
                            <span className="text-[9px] text-slate-500 block uppercase font-bold">Bytes</span>
                            <span className="font-bold text-slate-300 font-mono">{flow.bytes.toLocaleString()}</span>
                          </div>
                          <div>
                            <span className="text-[9px] text-slate-500 block uppercase font-bold">Duration</span>
                            <span className="font-bold text-slate-300 font-mono">{flow.duration.toFixed(2)}s</span>
                          </div>
                        </div>
                      </div>
                    ))}
                    {filteredFlows.length === 0 && (
                      <div className="col-span-2 text-center py-12 text-slate-500 font-bold">
                        No conversations found matching query
                      </div>
                    )}
                  </div>
                </div>
              )}

              {/* TAB 4: INTERACTIVE NETWORK GRAPH */}
              {activeTab === "graph" && (
                <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
                  
                  {/* Graph Canvas */}
                  <div className="bg-[#0b0e14]/40 border border-slate-900/80 backdrop-blur rounded-3xl p-6 md:col-span-3 flex flex-col items-center shadow-lg before:absolute before:top-0 before:left-0 before:w-full before:h-[1px] before:bg-gradient-to-r before:from-transparent before:via-slate-500/10 before:to-transparent">
                    <div className="w-full flex items-center justify-between mb-4">
                      <div>
                        <h3 className="text-xs font-bold uppercase tracking-wider text-slate-400">Topological Device Map</h3>
                        <p className="text-[11px] text-slate-500 font-bold uppercase mt-0.5">Click nodes to inspect device traffic parameters</p>
                      </div>
                      <div className="flex gap-4 text-xs font-semibold">
                        <div className="flex items-center gap-1.5">
                          <div className="w-2.5 h-2.5 rounded-full bg-cyan-400" />
                          <span className="text-slate-400">Clients</span>
                        </div>
                        <div className="flex items-center gap-1.5">
                          <div className="w-2.5 h-2.5 rounded-full bg-emerald-500" />
                          <span className="text-slate-400">Servers</span>
                        </div>
                        <div className="flex items-center gap-1.5">
                          <div className="w-2.5 h-2.5 rounded-full bg-purple-500" />
                          <span className="text-slate-400">Domains</span>
                        </div>
                      </div>
                    </div>
                    <canvas 
                      ref={canvasRef} 
                      width={800} 
                      height={500} 
                      className="bg-slate-950 rounded-2xl border border-slate-900 w-full shadow-inner cursor-pointer"
                    />
                  </div>

                  {/* Node Inspector */}
                  <div className="bg-[#0b0e14]/40 border border-slate-900/80 backdrop-blur rounded-3xl p-6 space-y-4 shadow-lg before:absolute before:top-0 before:left-0 before:w-full before:h-[1px] before:bg-gradient-to-r before:from-transparent before:via-slate-500/10 before:to-transparent">
                    <h3 className="text-xs font-bold uppercase tracking-wider text-slate-400">Node Inspector</h3>
                    
                    {selectedNode ? (
                      <div className="space-y-4">
                        <div className="bg-slate-950/60 p-3.5 border border-slate-900 rounded-xl shadow-inner">
                          <span className="text-[9px] text-slate-500 uppercase tracking-widest font-bold block">Device IP / SNI</span>
                          <span className="text-xs font-bold text-slate-200 break-all font-mono block mt-1">{selectedNode.id}</span>
                        </div>
                        <div className="bg-slate-950/60 p-3.5 border border-slate-900 rounded-xl shadow-inner">
                          <span className="text-[9px] text-slate-500 uppercase tracking-widest font-bold block">Node Type</span>
                          <span className="text-xs font-bold text-cyan-400 capitalize block mt-1">{selectedNode.type}</span>
                        </div>
                        <div className="bg-slate-950/60 p-3.5 border border-slate-900 rounded-xl shadow-inner">
                          <span className="text-[9px] text-slate-500 uppercase tracking-widest font-bold block">Total Packets Seen</span>
                          <span className="text-xs font-bold text-slate-300 font-mono block mt-1">{selectedNode.packets}</span>
                        </div>
                        <div className="bg-slate-950/60 p-3.5 border border-slate-900 rounded-xl shadow-inner">
                          <span className="text-[9px] text-slate-500 uppercase tracking-widest font-bold block">Total Traffic Size</span>
                          <span className="text-xs font-bold text-slate-300 font-mono block mt-1">{selectedNode.bytes.toLocaleString()} bytes</span>
                        </div>
                        
                        {/* List Node Connections */}
                        <div className="border-t border-slate-900/40 pt-3">
                          <h4 className="text-[9px] font-bold uppercase tracking-widest text-slate-500 mb-2">Connected Devices</h4>
                          <div className="space-y-2 max-h-48 overflow-y-auto custom-scroll pr-1">
                            {analysis.graph.edges.filter(e => e.source === selectedNode.id || e.target === selectedNode.id).map((edge, idx) => (
                              <div key={idx} className="bg-slate-950 p-2.5 border border-slate-900 rounded-xl text-xs">
                                <div className="flex justify-between text-slate-300 font-semibold font-mono">
                                  <span>{edge.source === selectedNode.id ? "→ " + edge.target.split(".")[3] || edge.target : "← " + edge.source}</span>
                                  <span className="text-cyan-400 font-bold text-[10px]">{edge.protocol}</span>
                                </div>
                                <div className="text-[10px] text-slate-500 mt-1 font-bold">
                                  {edge.packets} packets ({edge.bytes} B)
                                </div>
                              </div>
                            ))}
                          </div>
                        </div>
                      </div>
                    ) : (
                      <div className="text-center py-16 text-slate-600 flex flex-col items-center gap-3">
                        <Info className="w-8 h-8 text-slate-800" />
                        <span className="text-xs font-bold uppercase tracking-wide leading-normal">Select device node on topological map to inspect statistics</span>
                      </div>
                    )}
                  </div>
                </div>
              )}

              {/* TAB 5: RULES MANAGER */}
              {activeTab === "rules" && (
                <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                  
                  {/* IP Rules Card */}
                  <div className="bg-[#0b0e14]/40 border border-slate-900/80 backdrop-blur rounded-3xl p-6 space-y-4 flex flex-col shadow-lg before:absolute before:top-0 before:left-0 before:w-full before:h-[1px] before:bg-gradient-to-r before:from-transparent before:via-slate-500/10 before:to-transparent">
                    <h3 className="text-xs font-bold uppercase tracking-wider text-slate-400 flex items-center gap-2">
                      <Shield className="w-4 h-4 text-cyan-400" /> IP Blocking Rules
                    </h3>
                    <div className="flex gap-2">
                      <input 
                        type="text" 
                        placeholder="e.g. 192.168.1.50"
                        value={newIp}
                        onChange={(e) => setNewIp(e.target.value)}
                        className="bg-slate-950 text-xs rounded-lg px-3 py-2.5 border border-slate-900 focus:border-cyan-500/20 focus:outline-none grow"
                      />
                      <button 
                        onClick={() => handleBlockAction("ip", newIp)}
                        className="bg-cyan-500 hover:bg-cyan-400 text-black text-xs font-bold px-3 py-2.5 rounded-lg active:scale-95 transition-transform"
                      >
                        Block
                      </button>
                    </div>
                    <div className="bg-slate-950 rounded-xl border border-slate-900 p-3 grow max-h-60 overflow-y-auto custom-scroll space-y-2">
                      {rules.ips.map((ip, idx) => (
                        <div key={idx} className="flex justify-between items-center text-xs bg-[#0b0c10]/40 border border-slate-900/60 py-2 px-3 rounded-lg">
                          <span className="font-mono text-slate-300 font-bold">{ip}</span>
                          <span className="text-[10px] text-rose-400 font-extrabold">BLOCKED</span>
                        </div>
                      ))}
                      {rules.ips.length === 0 && (
                        <div className="text-center py-8 text-slate-600 text-xs font-bold">No active rules</div>
                      )}
                    </div>
                  </div>

                  {/* App Rules Card */}
                  <div className="bg-[#0b0e14]/40 border border-slate-900/80 backdrop-blur rounded-3xl p-6 space-y-4 flex flex-col shadow-lg before:absolute before:top-0 before:left-0 before:w-full before:h-[1px] before:bg-gradient-to-r before:from-transparent before:via-slate-500/10 before:to-transparent">
                    <h3 className="text-xs font-bold uppercase tracking-wider text-slate-400 flex items-center gap-2">
                      <ShieldAlert className="w-4 h-4 text-cyan-400" /> Application Blocking
                    </h3>
                    <div className="flex gap-2">
                      <input 
                        type="text" 
                        placeholder="e.g. YouTube, TikTok"
                        value={newApp}
                        onChange={(e) => setNewApp(e.target.value)}
                        className="bg-slate-950 text-xs rounded-lg px-3 py-2.5 border border-slate-900 focus:border-cyan-500/20 focus:outline-none grow"
                      />
                      <button 
                        onClick={() => handleBlockAction("app", newApp)}
                        className="bg-cyan-500 hover:bg-cyan-400 text-black text-xs font-bold px-3 py-2.5 rounded-lg active:scale-95 transition-transform"
                      >
                        Block
                      </button>
                    </div>
                    <div className="bg-slate-950 rounded-xl border border-slate-900 p-3 grow max-h-60 overflow-y-auto custom-scroll space-y-2">
                      {rules.apps.map((app, idx) => (
                        <div key={idx} className="flex justify-between items-center text-xs bg-[#0b0c10]/40 border border-slate-900/60 py-2 px-3 rounded-lg">
                          <span className="font-semibold text-slate-300 font-bold">{app}</span>
                          <span className="text-[10px] text-rose-400 font-extrabold">BLOCKED</span>
                        </div>
                      ))}
                      {rules.apps.length === 0 && (
                        <div className="text-center py-8 text-slate-600 text-xs font-bold">No active rules</div>
                      )}
                    </div>
                  </div>

                  {/* Domain Rules Card */}
                  <div className="bg-[#0b0e14]/40 border border-slate-900/80 backdrop-blur rounded-3xl p-6 space-y-4 flex flex-col shadow-lg before:absolute before:top-0 before:left-0 before:w-full before:h-[1px] before:bg-gradient-to-r before:from-transparent before:via-slate-500/10 before:to-transparent">
                    <h3 className="text-xs font-bold uppercase tracking-wider text-slate-400 flex items-center gap-2">
                      <Network className="w-4 h-4 text-cyan-400" /> Domain Substring Block
                    </h3>
                    <div className="flex gap-2">
                      <input 
                        type="text" 
                        placeholder="e.g. facebook, netflix"
                        value={newDomain}
                        onChange={(e) => setNewDomain(e.target.value)}
                        className="bg-slate-950 text-xs rounded-lg px-3 py-2.5 border border-slate-900 focus:border-cyan-500/20 focus:outline-none grow"
                      />
                      <button 
                        onClick={() => handleBlockAction("domain", newDomain)}
                        className="bg-cyan-500 hover:bg-cyan-400 text-black text-xs font-bold px-3 py-2.5 rounded-lg active:scale-95 transition-transform"
                      >
                        Block
                      </button>
                    </div>
                    <div className="bg-slate-950 rounded-xl border border-slate-900 p-3 grow max-h-60 overflow-y-auto custom-scroll space-y-2">
                      {rules.domains.map((dom, idx) => (
                        <div key={idx} className="flex justify-between items-center text-xs bg-[#0b0c10]/40 border border-slate-900/60 py-2 px-3 rounded-lg">
                          <span className="font-mono text-slate-300 font-bold">{dom}</span>
                          <span className="text-[10px] text-rose-400 font-extrabold">BLOCKED</span>
                        </div>
                      ))}
                      {rules.domains.length === 0 && (
                        <div className="text-center py-8 text-slate-600 text-xs font-bold">No active rules</div>
                      )}
                    </div>
                  </div>

                  {/* Clear Rules Buttons */}
                  <div className="md:col-span-3 flex justify-end">
                    <button 
                      onClick={handleClearRules}
                      className="px-5 py-2.5 bg-slate-950/80 hover:bg-slate-900 text-rose-400 hover:text-rose-300 font-bold border border-slate-900 rounded-xl text-xs uppercase tracking-wider transition-colors active:scale-95"
                    >
                      Clear All Active Rules
                    </button>
                  </div>

                </div>
              )}

              {/* TAB 6: EXPORT CENTER */}
              {activeTab === "export" && (
                <div className="max-w-md mx-auto bg-[#0b0e14]/40 border border-slate-900/80 backdrop-blur rounded-3xl p-8 text-center space-y-6 shadow-lg before:absolute before:top-0 before:left-0 before:w-full before:h-[1px] before:bg-gradient-to-r before:from-transparent before:via-slate-500/10 before:to-transparent">
                  <div className="w-16 h-16 bg-cyan-950/20 border border-cyan-800/30 rounded-2xl flex items-center justify-center mx-auto shadow-xl shadow-cyan-500/5">
                    <Database className="w-8 h-8 text-cyan-400" />
                  </div>
                  <div>
                    <h3 className="text-base font-bold text-slate-200">Analysis Export Center</h3>
                    <p className="text-xs text-slate-500 mt-1 leading-normal font-semibold">Download fully resolved analysis data in various structured formats powered by the Spring Boot backend reports exporter.</p>
                  </div>

                  <div className="grid grid-cols-1 gap-3">
                    <a 
                      href="http://localhost:8080/api/export?format=json"
                      download
                      className="flex items-center justify-between p-4 bg-slate-950/80 border border-slate-900 hover:border-slate-800 hover:bg-slate-900/30 rounded-2xl transition-all group shadow-sm"
                    >
                      <div className="flex items-center gap-3 text-left">
                        <FileJson className="w-5 h-5 text-amber-500" />
                        <div>
                          <span className="text-xs font-bold text-slate-300 block">Export JSON Report</span>
                          <span className="text-[10px] text-slate-500 font-medium">Raw structured metrics & flows</span>
                        </div>
                      </div>
                      <Download className="w-4 h-4 text-slate-500 group-hover:text-slate-300 transition-colors" />
                    </a>

                    <a 
                      href="http://localhost:8080/api/export?format=csv"
                      download
                      className="flex items-center justify-between p-4 bg-slate-950/80 border border-slate-900 hover:border-slate-800 hover:bg-slate-900/30 rounded-2xl transition-all group shadow-sm"
                    >
                      <div className="flex items-center gap-3 text-left">
                        <FileSpreadsheet className="w-5 h-5 text-emerald-500" />
                        <div>
                          <span className="text-xs font-bold text-slate-300 block">Export CSV Packet List</span>
                          <span className="text-[10px] text-slate-500 font-medium">Perfect for spreadsheets / database loads</span>
                        </div>
                      </div>
                      <Download className="w-4 h-4 text-slate-500 group-hover:text-slate-300 transition-colors" />
                    </a>

                    <a 
                      href="http://localhost:8080/api/export?format=html"
                      download
                      className="flex items-center justify-between p-4 bg-slate-950/80 border border-slate-900 hover:border-slate-800 hover:bg-slate-900/30 rounded-2xl transition-all group shadow-sm"
                    >
                      <div className="flex items-center gap-3 text-left">
                        <FileCode className="w-5 h-5 text-cyan-500" />
                        <div>
                          <span className="text-xs font-bold text-slate-300 block">Export HTML Report</span>
                          <span className="text-[10px] text-slate-500 font-medium">Clean print-ready document overview</span>
                        </div>
                      </div>
                      <Download className="w-4 h-4 text-slate-500 group-hover:text-slate-300 transition-colors" />
                    </a>
                  </div>

                  <div className="pt-4 border-t border-slate-900/40">
                    <button 
                      onClick={() => setAnalysis(null)}
                      className="text-xs font-bold text-slate-400 hover:text-slate-200 transition-colors"
                    >
                      Upload Another PCAP File
                    </button>
                  </div>
                </div>
              )}

            </motion.div>
          )}

        </AnimatePresence>
      </main>

      {/* Bottom Footer */}
      <footer className="py-10 text-center text-[10px] font-extrabold text-slate-600 border-t border-slate-900/60 mt-16 tracking-widest relative z-10">
        <p>POWERED BY THE CORE JAVA DEEP PACKET INSPECTION (DPI) ENGINE</p>
      </footer>
    </div>
  );
}
