package com.packetanalyzer.controller;

import com.packetanalyzer.config.DPIEngineConfig;
import com.packetanalyzer.service.DPIEngine;
import java.util.ArrayList;
import java.util.List;

public class MainController {

    private static void printUsage(String program) {
        System.out.println("""
╔══════════════════════════════════════════════════════════════╗
║                    DPI ENGINE v1.0                            ║
║               Deep Packet Inspection System                   ║
╚══════════════════════════════════════════════════════════════╝

Usage: """ + program + """
 <input.pcap> <output.pcap> [options]

Arguments:
  input.pcap     Input PCAP file (captured user traffic)
  output.pcap    Output PCAP file (filtered traffic to internet)

Options:
  --block-ip <ip>        Block packets from source IP
  --block-app <app>      Block application (e.g., YouTube, Facebook)
  --block-domain <dom>   Block domain (supports wildcards: *.facebook.com)
  --rules <file>         Load blocking rules from file
  --lbs <n>              Number of load balancer threads (default: 2)
  --fps <n>              FP threads per LB (default: 2)
  --verbose              Enable verbose output

Examples:
  """ + program + """
 capture.pcap filtered.pcap
  """ + program + """
 capture.pcap filtered.pcap --block-app YouTube
  """ + program + """
 capture.pcap filtered.pcap --block-ip 192.168.1.50 --block-domain *.tiktok.com
  """ + program + """
 capture.pcap filtered.pcap --rules blocking_rules.txt

Supported Apps for Blocking:
  Google, YouTube, Facebook, Instagram, Twitter/X, Netflix, Amazon,
  Microsoft, Apple, WhatsApp, Telegram, TikTok, Spotify, Zoom, Discord, GitHub

Architecture:
  ┌─────────────┐
  │ PCAP Reader │  Reads packets from input file
  └──────┬──────┘
         │ hash(5-tuple) % num_lbs
         ▼
  ┌──────┴──────┐
  │ Load Balancer │  2 LB threads distribute to FPs
  │   LB0 │ LB1   │
  └──┬────┴────┬──┘
     │         │  hash(5-tuple) % fps_per_lb
     ▼         ▼
  ┌──┴──┐   ┌──┴──┐
  │FP0-1│   │FP2-3│  4 FP threads: DPI, classification, blocking
  └──┬──┘   └──┬──┘
     │         │
     ▼         ▼
  ┌──┴─────────┴──┐
  │ Output Writer │  Writes forwarded packets to output
  └───────────────┘
""");
    }

    public static void main(String[] args) {
        if (args.length < 2) {
            printUsage("java -jar java-packet-analyzer.jar");
            System.exit(1);
        }

        String inputFile = args[0];
        String outputFile = args[1];

        DPIEngineConfig config = new DPIEngineConfig();
        config.numLoadBalancers = 2;
        config.fpsPerLb = 2;
        config.verbose = false;

        List<String> blockIps = new ArrayList<>();
        List<String> blockApps = new ArrayList<>();
        List<String> blockDomains = new ArrayList<>();
        String rulesFile = "";

        for (int i = 2; i < args.length; i++) {
            String arg = args[i];

            if (arg.equals("--block-ip") && i + 1 < args.length) {
                blockIps.add(args[++i]);
            } else if (arg.equals("--block-app") && i + 1 < args.length) {
                blockApps.add(args[++i]);
            } else if (arg.equals("--block-domain") && i + 1 < args.length) {
                blockDomains.add(args[++i]);
            } else if (arg.equals("--rules") && i + 1 < args.length) {
                rulesFile = args[++i];
            } else if (arg.equals("--lbs") && i + 1 < args.length) {
                config.numLoadBalancers = Integer.parseInt(args[++i]);
            } else if (arg.equals("--fps") && i + 1 < args.length) {
                config.fpsPerLb = Integer.parseInt(args[++i]);
            } else if (arg.equals("--verbose")) {
                config.verbose = true;
            } else if (arg.equals("--help") || arg.equals("-h")) {
                printUsage("java -jar java-packet-analyzer.jar");
                System.exit(0);
            }
        }

        DPIEngine engine = new DPIEngine(config);

        if (!engine.initialize()) {
            System.err.println("Failed to initialize DPI engine");
            System.exit(1);
        }

        if (!rulesFile.isEmpty()) {
            engine.loadRules(rulesFile);
        }

        for (String ip : blockIps) {
            engine.blockIP(ip);
        }

        for (String app : blockApps) {
            engine.blockApp(app);
        }

        for (String domain : blockDomains) {
            engine.blockDomain(domain);
        }

        if (!engine.processFile(inputFile, outputFile)) {
            System.err.println("Failed to process file");
            System.exit(1);
        }

        System.out.println("\nProcessing complete!");
        System.out.println("Output written to: " + outputFile);
    }
}
