package com.packetanalyzer.protocol;

import java.nio.charset.StandardCharsets;
import java.util.Optional;

public class HttpHostExtractor {

    public static boolean isHTTPRequest(byte[] payload, int length) {
        if (length < 4) return false;
        String method = new String(payload, 0, 4, StandardCharsets.US_ASCII);
        return method.equals("GET ") || method.equals("POST") || method.equals("PUT ") ||
               method.equals("HEAD") || method.equals("DELE") || method.equals("PATC") ||
               method.equals("OPTI");
    }

    public static Optional<String> extract(byte[] payload, int length) {
        if (!isHTTPRequest(payload, length)) {
            return Optional.empty();
        }

        // Search for case-insensitive "Host: " header
        for (int i = 0; i + 6 < length; i++) {
            if ((payload[i] == 'H' || payload[i] == 'h') &&
                (payload[i+1] == 'o' || payload[i+1] == 'O') &&
                (payload[i+2] == 's' || payload[i+2] == 'S') &&
                (payload[i+3] == 't' || payload[i+3] == 'T') &&
                payload[i+4] == ':') {
                
                int start = i + 5;
                // Skip spaces or tabs
                while (start < length && (payload[start] == ' ' || payload[start] == '\t')) {
                    start++;
                }

                int end = start;
                while (end < length && payload[end] != '\r' && payload[end] != '\n') {
                    end++;
                }

                if (end > start) {
                    String host = new String(payload, start, end - start, StandardCharsets.US_ASCII);
                    // Remove port if present
                    int colonPos = host.indexOf(':');
                    if (colonPos != -1) {
                        host = host.substring(0, colonPos);
                    }
                    return Optional.of(host.trim());
                }
            }
        }

        return Optional.empty();
    }
}
