package com.packetanalyzer.flow;

import com.packetanalyzer.model.AppType;
import com.packetanalyzer.model.FiveTuple;
import com.packetanalyzer.model.PacketAction;

public class Connection {
    public FiveTuple tuple;
    public ConnectionState state = ConnectionState.NEW;
    public AppType appType = AppType.UNKNOWN;
    public String sni = "";

    public long packetsIn = 0;
    public long packetsOut = 0;
    public long bytesIn = 0;
    public long bytesOut = 0;

    public long firstSeen;
    public long lastSeen;

    public PacketAction action = PacketAction.FORWARD;

    // For TCP state tracking
    public boolean synSeen = false;
    public boolean synAckSeen = false;
    public boolean finSeen = false;

    public Connection() {
        this.firstSeen = System.currentTimeMillis();
        this.lastSeen = this.firstSeen;
    }
}
