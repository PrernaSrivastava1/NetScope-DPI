package com.packetanalyzer.parser;

import com.packetanalyzer.model.RawPacket;
import com.packetanalyzer.model.ParsedPacket;
import com.packetanalyzer.utils.ByteUtils;

public class PacketParser {

    // Protocol numbers
    public static final int PROTOCOL_ICMP = 1;
    public static final int PROTOCOL_TCP = 6;
    public static final int PROTOCOL_UDP = 17;

    // EtherType values
    public static final int ETHERTYPE_IPV4 = 0x0800;
    public static final int ETHERTYPE_IPV6 = 0x86DD;
    public static final int ETHERTYPE_ARP = 0x0806;

    // TCP Flags
    public static final int TCP_FLAG_FIN = 0x01;
    public static final int TCP_FLAG_SYN = 0x02;
    public static final int TCP_FLAG_RST = 0x04;
    public static final int TCP_FLAG_PSH = 0x08;
    public static final int TCP_FLAG_ACK = 0x10;
    public static final int TCP_FLAG_URG = 0x20;

    public static boolean parse(RawPacket raw, ParsedPacket parsed) {
        parsed.setTimestampSec(raw.getHeader().getTsSec());
        parsed.setTimestampUsec(raw.getHeader().getTsUsec());
        parsed.setSrcMac(null);
        parsed.setDestMac(null);
        parsed.setEtherType(0);
        parsed.setHasIp(false);
        parsed.setIpVersion(0);
        parsed.setSrcIp(null);
        parsed.setDestIp(null);
        parsed.setProtocol(0);
        parsed.setTtl(0);
        parsed.setHasTcp(false);
        parsed.setHasUdp(false);
        parsed.setSrcPort(0);
        parsed.setDestPort(0);
        parsed.setTcpFlags(0);
        parsed.setSeqNumber(0);
        parsed.setAckNumber(0);
        parsed.setPayloadLength(0);
        parsed.setPayloadOffset(0);
        parsed.setPayloadData(null);

        byte[] data = raw.getData();
        int len = data.length;
        int[] offset = new int[]{0};

        // Parse Ethernet Header
        if (!parseEthernet(data, len, parsed, offset)) {
            return false;
        }

        // Parse IP Layer if IPv4
        if (parsed.getEtherType() == ETHERTYPE_IPV4) {
            if (!parseIPv4(data, len, parsed, offset)) {
                return false;
            }

            // Parse Transport Layer based on Protocol
            if (parsed.getProtocol() == PROTOCOL_TCP) {
                if (!parseTCP(data, len, parsed, offset)) {
                    return false;
                }
            } else if (parsed.getProtocol() == PROTOCOL_UDP) {
                if (!parseUDP(data, len, parsed, offset)) {
                    return false;
                }
            }
        }

        // Set Payload
        if (offset[0] < len) {
            parsed.setPayloadLength(len - offset[0]);
            parsed.setPayloadOffset(offset[0]);
            // Slice the data array for payload reference
            byte[] payload = new byte[len - offset[0]];
            System.arraycopy(data, offset[0], payload, 0, payload.length);
            parsed.setPayloadData(payload);
        } else {
            parsed.setPayloadLength(0);
            parsed.setPayloadOffset(offset[0]);
            parsed.setPayloadData(new byte[0]);
        }

        return true;
    }

    private static boolean parseEthernet(byte[] data, int len, ParsedPacket parsed, int[] offset) {
        if (len < 14) {
            return false; // Packet too short
        }

        parsed.setDestMac(ByteUtils.macToString(data, 0));
        parsed.setSrcMac(ByteUtils.macToString(data, 6));
        parsed.setEtherType(ByteUtils.readUint16BE(data, 12));

        offset[0] = 14;
        return true;
    }

    private static boolean parseIPv4(byte[] data, int len, ParsedPacket parsed, int[] offset) {
        if (len < offset[0] + 20) {
            return false;
        }

        int ipStart = offset[0];
        int versionIhl = data[ipStart] & 0xFF;
        int version = (versionIhl >> 4) & 0x0F;
        int ihl = versionIhl & 0x0F; // Header length in 32-bit words

        if (version != 4) {
            return false; // Not IPv4
        }

        int ipHeaderLen = ihl * 4;
        if (ipHeaderLen < 20 || len < ipStart + ipHeaderLen) {
            return false;
        }

        parsed.setIpVersion(4);
        parsed.setTtl(data[ipStart + 8] & 0xFF);
        parsed.setProtocol(data[ipStart + 9] & 0xFF);

        // Read source and destination IPs as little-endian to align with C++ memory layout on x86
        int srcIp = ByteUtils.readInt32LE(data, ipStart + 12);
        int destIp = ByteUtils.readInt32LE(data, ipStart + 16);

        parsed.setSrcIp(com.packetanalyzer.model.FiveTuple.ipToString(srcIp));
        parsed.setDestIp(com.packetanalyzer.model.FiveTuple.ipToString(destIp));
        parsed.setHasIp(true);

        offset[0] += ipHeaderLen;
        return true;
    }

    private static boolean parseTCP(byte[] data, int len, ParsedPacket parsed, int[] offset) {
        if (len < offset[0] + 20) {
            return false;
        }

        int tcpStart = offset[0];
        parsed.setSrcPort(ByteUtils.readUint16BE(data, tcpStart));
        parsed.setDestPort(ByteUtils.readUint16BE(data, tcpStart + 2));
        parsed.setSeqNumber(ByteUtils.readUint32BE(data, tcpStart + 4));
        parsed.setAckNumber(ByteUtils.readUint32BE(data, tcpStart + 8));

        int dataOffset = ((data[tcpStart + 12] & 0xFF) >> 4) & 0x0F;
        int tcpHeaderLen = dataOffset * 4;

        parsed.setTcpFlags(data[tcpStart + 13] & 0xFF);

        if (tcpHeaderLen < 20 || len < tcpStart + tcpHeaderLen) {
            return false;
        }

        parsed.setHasTcp(true);
        offset[0] += tcpHeaderLen;
        return true;
    }

    private static boolean parseUDP(byte[] data, int len, ParsedPacket parsed, int[] offset) {
        if (len < offset[0] + 8) {
            return false;
        }

        int udpStart = offset[0];
        parsed.setSrcPort(ByteUtils.readUint16BE(data, udpStart));
        parsed.setDestPort(ByteUtils.readUint16BE(data, udpStart + 2));

        parsed.setHasUdp(true);
        offset[0] += 8;
        return true;
    }

    public static String protocolToString(int protocol) {
        switch (protocol) {
            case PROTOCOL_ICMP: return "ICMP";
            case PROTOCOL_TCP:  return "TCP";
            case PROTOCOL_UDP:  return "UDP";
            default: return "Unknown(" + protocol + ")";
        }
    }

    public static String tcpFlagsToString(int flags) {
        StringBuilder sb = new StringBuilder();
        if ((flags & TCP_FLAG_SYN) != 0) sb.append("SYN ");
        if ((flags & TCP_FLAG_ACK) != 0) sb.append("ACK ");
        if ((flags & TCP_FLAG_FIN) != 0) sb.append("FIN ");
        if ((flags & TCP_FLAG_RST) != 0) sb.append("RST ");
        if ((flags & TCP_FLAG_PSH) != 0) sb.append("PSH ");
        if ((flags & TCP_FLAG_URG) != 0) sb.append("URG ");
        if (sb.length() > 0) sb.setLength(sb.length() - 1); // remove trailing space
        return sb.length() == 0 ? "none" : sb.toString();
    }
}
