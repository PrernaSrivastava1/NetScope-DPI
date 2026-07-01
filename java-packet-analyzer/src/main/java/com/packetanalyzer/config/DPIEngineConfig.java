package com.packetanalyzer.config;

public class DPIEngineConfig {
    public int numLoadBalancers = 2;
    public int fpsPerLb = 2;
    public int queueSize = 10000;
    public String rulesFile = "";
    public boolean verbose = false;
}
