package com.packetanalyzer.controller;

import com.packetanalyzer.model.RawPacket;
import com.packetanalyzer.model.ParsedPacket;
import com.packetanalyzer.parser.PcapReader;
import com.packetanalyzer.parser.PacketParser;
import com.packetanalyzer.protocol.TlsSniExtractor;
import java.util.Optional;

public class MainSimple {
    public static void main(String[] args) {
        if (args.length < 1) {
            System.err.println("Usage: java com.packetanalyzer.controller.MainSimple <pcap_file>");
            System.exit(1);
        }

        PcapReader reader = new PcapReader();
        if (!reader.open(args[0])) {
            System.exit(1);
        }

        RawPacket[] rawRef = new RawPacket[1];
        ParsedPacket parsed = new ParsedPacket();
        int count = 0;
        int tlsCount = 0;

        System.out.println("Processing packets...");

        while (reader.readNextPacket(rawRef)) {
            count++;
            RawPacket raw = rawRef[0];

            if (!PacketParser.parse(raw, parsed)) {
                continue;
            }

            if (!parsed.isHasIp()) {
                continue;
            }

            System.out.print("Packet " + count + ": " 
                    + parsed.getSrcIp() + ":" + parsed.getSrcPort()
                    + " -> " + parsed.getDestIp() + ":" + parsed.getDestPort());

            // Try SNI extraction for HTTPS packets
            if (parsed.isHasTcp() && parsed.getDestPort() == 443 && parsed.getPayloadLength() > 0) {
                // Calculate payload offset
                int payloadOffset = 14; // Ethernet
                int ipIhl = raw.getData()[14] & 0x0F;
                payloadOffset += ipIhl * 4;
                int tcpOffset = ((raw.getData()[payloadOffset + 12] & 0xFF) >> 4) & 0x0F;
                payloadOffset += tcpOffset * 4;

                if (payloadOffset < raw.getData().length) {
                    int payloadLen = raw.getData().length - payloadOffset;
                    byte[] payload = new byte[payloadLen];
                    System.arraycopy(raw.getData(), payloadOffset, payload, 0, payloadLen);
                    Optional<String> sni = TlsSniExtractor.extract(payload, payloadLen);
                    if (sni.isPresent()) {
                        System.out.print(" [SNI: " + sni.get() + "]");
                        tlsCount++;
                    }
                }
            }

            System.out.println();
        }

        System.out.println("\nTotal packets: " + count);
        System.out.println("SNI extracted: " + tlsCount);

        reader.close();
    }
}
