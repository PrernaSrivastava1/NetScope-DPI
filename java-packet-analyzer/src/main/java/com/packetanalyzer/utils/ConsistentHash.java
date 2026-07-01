package com.packetanalyzer.utils;

import com.packetanalyzer.model.FiveTuple;

public class ConsistentHash {

    public static int getLBIndex(FiveTuple tuple, int numLbs) {
        if (numLbs <= 0) return 0;
        long hash = tuple.getConsistentHash();
        return (int) Long.remainderUnsigned(hash, numLbs);
    }

    public static int getFPIndex(FiveTuple tuple, int numFps) {
        if (numFps <= 0) return 0;
        long hash = tuple.getConsistentHash();
        return (int) Long.remainderUnsigned(hash, numFps);
    }
}
