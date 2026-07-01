package com.packetanalyzer.protocol;

import com.packetanalyzer.model.RawPacket;
import com.packetanalyzer.model.ParsedPacket;
import com.packetanalyzer.parser.PcapReader;
import com.packetanalyzer.parser.PacketParser;
import org.junit.jupiter.api.Test;
import java.io.File;
import java.util.Optional;
import static org.junit.jupiter.api.Assertions.*;

public class ProtocolExtractorTest {

    @Test
    public void testProtocolExtractionOnPcap() {
        String pcapPath = ".." + File.separator + "test_dpi.pcap";
        File file = new File(pcapPath);
        assertTrue(file.exists());

        try (PcapReader reader = new PcapReader()) {
            assertTrue(reader.open(pcapPath));

            RawPacket[] packetRef = new RawPacket[1];
            int tlsSniCount = 0;
            int httpHostCount = 0;
            int dnsDomainCount = 0;

            while (reader.readNextPacket(packetRef)) {
                RawPacket raw = packetRef[0];
                ParsedPacket parsed = new ParsedPacket();
                if (PacketParser.parse(raw, parsed) && parsed.isHasIp()) {
                    byte[] payload = parsed.getPayloadData();
                    int payloadLen = parsed.getPayloadLength();

                    if (payloadLen > 0) {
                        if (parsed.isHasTcp()) {
                            if (parsed.getDestPort() == 443) {
                                Optional<String> sni = TlsSniExtractor.extract(payload, payloadLen);
                                if (sni.isPresent()) {
                                    tlsSniCount++;
                                    System.out.println("Extracted TLS SNI: " + sni.get());
                                }
                            } else if (parsed.getDestPort() == 80) {
                                Optional<String> host = HttpHostExtractor.extract(payload, payloadLen);
                                if (host.isPresent()) {
                                    httpHostCount++;
                                    System.out.println("Extracted HTTP Host: " + host.get());
                                }
                            }
                        } else if (parsed.isHasUdp()) {
                            if (parsed.getDestPort() == 53 || parsed.getSrcPort() == 53) {
                                Optional<String> query = DnsExtractor.extractQuery(payload, payloadLen);
                                if (query.isPresent()) {
                                    dnsDomainCount++;
                                    System.out.println("Extracted DNS Query Domain: " + query.get());
                                }
                            }
                        }
                    }
                }
            }

            assertEquals(16, tlsSniCount, "Should extract exactly 16 TLS SNIs");
            assertEquals(2, httpHostCount, "Should extract exactly 2 HTTP Hosts");
            assertEquals(4, dnsDomainCount, "Should extract exactly 4 DNS domains");
        }
    }
}
