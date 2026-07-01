package com.packetanalyzer.protocol;

import com.packetanalyzer.utils.ByteUtils;
import java.nio.charset.StandardCharsets;
import java.util.Optional;

public class DnsExtractor {

    public static boolean isDNSQuery(byte[] payload, int length) {
        if (length < 12) return false;

        // Check QR bit (byte 2, bit 7) - should be 0 for query
        int flags = payload[2] & 0xFF;
        if ((flags & 0x80) != 0) return false; // Response

        // Check QDCOUNT (bytes 4-5) - should be > 0
        int qdcount = ByteUtils.readUint16BE(payload, 4);
        if (qdcount == 0) return false;

        return true;
    }

    public static Optional<String> extractQuery(byte[] payload, int length) {
        if (!isDNSQuery(payload, length)) {
            return Optional.empty();
        }

        int offset = 12;
        StringBuilder domain = new StringBuilder();

        while (offset < length) {
            int labelLength = payload[offset] & 0xFF;

            if (labelLength == 0) {
                break; // End of domain name
            }

            if (labelLength > 63) {
                break; // Compression pointer or invalid label
            }

            offset++;
            if (offset + labelLength > length) break;

            if (domain.length() > 0) {
                domain.append('.');
            }
            domain.append(new String(payload, offset, labelLength, StandardCharsets.US_ASCII));
            offset += labelLength;
        }

        return domain.length() == 0 ? Optional.empty() : Optional.of(domain.toString());
    }
}
