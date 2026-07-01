package com.packetanalyzer.service;

import com.packetanalyzer.model.FiveTuple;
import com.packetanalyzer.model.PacketJob;
import com.packetanalyzer.utils.ConsistentHash;

import java.util.*;
import java.util.concurrent.BlockingQueue;

public class LBManager {
    private final List<LoadBalancer> lbs = new ArrayList<>();
    private final int fpsPerLb;

    public LBManager(int numLbs, int fpsPerLb, List<BlockingQueue<PacketJob>> fpQueues) {
        this.fpsPerLb = fpsPerLb;

        for (int lbId = 0; lbId < numLbs; lbId++) {
            List<BlockingQueue<PacketJob>> lbFpQueues = new ArrayList<>();
            int fpStart = lbId * fpsPerLb;

            for (int i = 0; i < fpsPerLb; i++) {
                lbFpQueues.add(fpQueues.get(fpStart + i));
            }

            lbs.add(new LoadBalancer(lbId, lbFpQueues, fpStart));
        }

        System.out.println("[LBManager] Created " + numLbs + " load balancers, " + fpsPerLb + " FPs each");
    }

    public void startAll() {
        for (LoadBalancer lb : lbs) {
            lb.start();
        }
    }

    public void stopAll() {
        for (LoadBalancer lb : lbs) {
            lb.stop();
        }
    }

    public LoadBalancer getLBForPacket(FiveTuple tuple) {
        int lbIndex = ConsistentHash.getLBIndex(tuple, lbs.size());
        return lbs.get(lbIndex);
    }

    public LoadBalancer getLB(int id) {
        return lbs.get(id);
    }

    public int getNumLBs() {
        return lbs.size();
    }

    public AggregatedLBStats getAggregatedStats() {
        long totalReceived = 0;
        long totalDispatched = 0;

        for (LoadBalancer lb : lbs) {
            totalReceived += lb.getPacketsReceived();
            totalDispatched += lb.getPacketsDispatched();
        }

        return new AggregatedLBStats(totalReceived, totalDispatched);
    }

    public static class AggregatedLBStats {
        public final long totalReceived;
        public final long totalDispatched;

        public AggregatedLBStats(long totalReceived, long totalDispatched) {
            this.totalReceived = totalReceived;
            this.totalDispatched = totalDispatched;
        }
    }
}
