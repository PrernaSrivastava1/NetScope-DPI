package com.packetanalyzer.model;

public enum PacketAction {
    FORWARD,    // Send to internet
    DROP,       // Block/drop the packet
    INSPECT,    // Needs further inspection
    LOG_ONLY    // Forward but log
}
