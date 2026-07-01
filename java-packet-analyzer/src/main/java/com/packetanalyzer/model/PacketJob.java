package com.packetanalyzer.model;

public class PacketJob {
    private int packetId;
    private FiveTuple tuple;
    private byte[] data;
    private int ethOffset = 0;
    private int ipOffset = 0;
    private int transportOffset = 0;
    private int payloadOffset = 0;
    private int payloadLength = 0;
    private int tcpFlags = 0;

    // Timestamps
    private int tsSec;
    private int tsUsec;

    public int getPacketId() {
        return packetId;
    }

    public void setPacketId(int packetId) {
        this.packetId = packetId;
    }

    public FiveTuple getTuple() {
        return tuple;
    }

    public void setTuple(FiveTuple tuple) {
        this.tuple = tuple;
    }

    public byte[] getData() {
        return data;
    }

    public void setData(byte[] data) {
        this.data = data;
    }

    public int getEthOffset() {
        return ethOffset;
    }

    public void setEthOffset(int ethOffset) {
        this.ethOffset = ethOffset;
    }

    public int getIpOffset() {
        return ipOffset;
    }

    public void setIpOffset(int ipOffset) {
        this.ipOffset = ipOffset;
    }

    public int getTransportOffset() {
        return transportOffset;
    }

    public void setTransportOffset(int transportOffset) {
        this.transportOffset = transportOffset;
    }

    public int getPayloadOffset() {
        return payloadOffset;
    }

    public void setPayloadOffset(int payloadOffset) {
        this.payloadOffset = payloadOffset;
    }

    public int getPayloadLength() {
        return payloadLength;
    }

    public void setPayloadLength(int payloadLength) {
        this.payloadLength = payloadLength;
    }

    public int getTcpFlags() {
        return tcpFlags;
    }

    public void setTcpFlags(int tcpFlags) {
        this.tcpFlags = tcpFlags;
    }

    public int getTsSec() {
        return tsSec;
    }

    public void setTsSec(int tsSec) {
        this.tsSec = tsSec;
    }

    public int getTsUsec() {
        return tsUsec;
    }

    public void setTsUsec(int tsUsec) {
        this.tsUsec = tsUsec;
    }
}
