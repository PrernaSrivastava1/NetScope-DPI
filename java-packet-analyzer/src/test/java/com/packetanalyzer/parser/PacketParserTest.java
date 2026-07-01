package com.packetanalyzer.parser;

import com.packetanalyzer.model.RawPacket;
import com.packetanalyzer.model.ParsedPacket;
import org.junit.jupiter.api.Test;
import java.io.File;
import static org.junit.jupiter.api.Assertions.*;

public class PacketParserTest {

    @Test
    public void testPcapReadingAndParsing() {
        // Path to the test pcap in the workspace
        String pcapPath = ".." + File.separator + "test_dpi.pcap";
        File file = new File(pcapPath);
        assertTrue(file.exists(), "test_dpi.pcap must exist in the workspace parent directory");

        try (PcapReader reader = new PcapReader()) {
            assertTrue(reader.open(pcapPath));
            assertEquals(1, reader.getNetwork(), "Network link type should be 1 (Ethernet)");
            assertNotNull(reader.getGlobalHeaderBytes());
            assertEquals(24, reader.getGlobalHeaderBytes().length);

            RawPacket[] packetRef = new RawPacket[1];
            int count = 0;
            int ipCount = 0;
            int tcpCount = 0;
            int udpCount = 0;

            while (reader.readNextPacket(packetRef)) {
                count++;
                RawPacket raw = packetRef[0];
                assertNotNull(raw);
                assertNotNull(raw.getData());
                assertTrue(raw.getData().length > 0);

                ParsedPacket parsed = new ParsedPacket();
                boolean parsedSuccess = PacketParser.parse(raw, parsed);
                assertTrue(parsedSuccess, "Packet #" + count + " parsing should succeed");

                if (parsed.isHasIp()) {
                    ipCount++;
                    assertNotNull(parsed.getSrcIp());
                    assertNotNull(parsed.getDestIp());

                    if (parsed.isHasTcp()) {
                        tcpCount++;
                        assertTrue(parsed.getSrcPort() > 0);
                        assertTrue(parsed.getDestPort() > 0);
                    } else if (parsed.isHasUdp()) {
                        udpCount++;
                        assertTrue(parsed.getSrcPort() > 0);
                        assertTrue(parsed.getDestPort() > 0);
                    }
                }
            }

            assertEquals(77, count, "Total packets read should be 77");
            assertTrue(ipCount > 0, "Should have parsed IP packets");
            assertTrue(tcpCount > 0, "Should have parsed TCP packets");
            assertTrue(udpCount > 0, "Should have parsed UDP packets");

            System.out.println("Test Pcap Summary: Total Packets = " + count +
                               ", IP = " + ipCount + ", TCP = " + tcpCount + ", UDP = " + udpCount);
        }
    }
}
