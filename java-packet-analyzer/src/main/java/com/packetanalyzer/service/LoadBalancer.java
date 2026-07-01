package com.packetanalyzer.service;

import com.packetanalyzer.model.PacketJob;
import com.packetanalyzer.utils.ConsistentHash;

import java.util.*;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

public class LoadBalancer implements Runnable {
    private final int lbId;
    private final int fpStartId;
    private final int numFps;
    private final BlockingQueue<PacketJob> inputQueue;
    private final List<BlockingQueue<PacketJob>> fpQueues;

    // Statistics
    private final AtomicLong packetsReceived = new AtomicLong(0);
    private final AtomicLong packetsDispatched = new AtomicLong(0);
    private final long[] perFpCounts;

    private volatile boolean running = false;
    private Thread thread;

    public LoadBalancer(int lbId, List<BlockingQueue<PacketJob>> fpQueues, int fpStartId) {
        this.lbId = lbId;
        this.fpStartId = fpStartId;
        this.fpQueues = fpQueues;
        this.numFps = fpQueues.size();
        this.inputQueue = new ArrayBlockingQueue<>(10000);
        this.perFpCounts = new long[numFps];
    }

    public int getId() {
        return lbId;
    }

    public BlockingQueue<PacketJob> getInputQueue() {
        return inputQueue;
    }

    public void start() {
        if (running) return;
        running = true;
        thread = new Thread(this, "LB-" + lbId);
        thread.start();
        System.out.println("[LB" + lbId + "] Started (serving FP" + fpStartId + "-FP" + (fpStartId + numFps - 1) + ")");
    }

    public void stop() {
        if (!running) return;
        running = false;
        if (thread != null) {
            try {
                thread.join(1000);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
        System.out.println("[LB" + lbId + "] Stopped");
    }

    @Override
    public void run() {
        while (running) {
            try {
                // Pop with timeout to check running flag (similar to popWithTimeout in C++)
                PacketJob job = inputQueue.poll(100, TimeUnit.MILLISECONDS);
                if (job == null) {
                    continue;
                }

                packetsReceived.incrementAndGet();

                // Consistent hash to select target FP
                int fpIndex = ConsistentHash.getFPIndex(job.getTuple(), numFps);

                // Push to target FP
                fpQueues.get(fpIndex).put(job);

                packetsDispatched.incrementAndGet();
                perFpCounts[fpIndex]++;
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            }
        }
    }

    public long getPacketsReceived() {
        return packetsReceived.get();
    }

    public long getPacketsDispatched() {
        return packetsDispatched.get();
    }

    public long[] getPerFpCounts() {
        return perFpCounts;
    }

    public boolean isRunning() {
        return running;
    }
}
