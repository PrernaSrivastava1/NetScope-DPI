package com.packetanalyzer.service;

import com.packetanalyzer.model.PacketAction;
import com.packetanalyzer.model.PacketJob;

@FunctionalInterface
public interface PacketOutputCallback {
    void handle(PacketJob job, PacketAction action);
}
