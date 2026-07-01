package com.packetanalyzer.service;

import com.packetanalyzer.config.DPIEngineConfig;
import com.packetanalyzer.model.DPIStats;
import org.junit.jupiter.api.Test;
import java.io.File;
import static org.junit.jupiter.api.Assertions.*;

public class DPIEngineTest {

    @Test
    public void testDPIEngineProcessing() {
        String pcapPath = ".." + File.separator + "test_dpi.pcap";
        String outputPath = "temp_output.pcap";

        File inputFile = new File(pcapPath);
        assertTrue(inputFile.exists(), "test_dpi.pcap must exist in the workspace parent");

        File outputFile = new File(outputPath);
        if (outputFile.exists()) {
            outputFile.delete();
        }

        DPIEngineConfig config = new DPIEngineConfig();
        config.numLoadBalancers = 2;
        config.fpsPerLb = 2;
        config.rulesFile = "";
        config.verbose = true;

        DPIEngine engine = new DPIEngine(config);
        
        // Block IP and App to check filtering statistics
        engine.blockIP("192.168.1.50");
        engine.blockApp("YouTube");
        engine.blockApp("TikTok");
        engine.blockDomain("facebook");

        boolean success = engine.processFile(pcapPath, outputPath);
        assertTrue(success, "DPIEngine processing should succeed");
        assertTrue(outputFile.exists(), "Output PCAP should be written to disk");

        DPIStats stats = engine.getStats();
        
        // C++ outputs: 77 packets, 8 dropped, 69 forwarded
        // Let's assert these exact counters!
        assertEquals(77, stats.totalPackets.get(), "Total packets must be 77");
        assertEquals(8, stats.droppedPackets.get(), "Dropped packets must be 8");
        assertEquals(69, stats.forwardedPackets.get(), "Forwarded packets must be 69");
        assertEquals(73, stats.tcpPackets.get(), "TCP packets must be 73");
        assertEquals(4, stats.udpPackets.get(), "UDP packets must be 4");

        // Clean up
        outputFile.delete();
    }
}
