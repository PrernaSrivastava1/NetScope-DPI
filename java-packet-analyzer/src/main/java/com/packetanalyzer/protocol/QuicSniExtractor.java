package com.packetanalyzer.protocol;

import java.util.Optional;

public class QuicSniExtractor {

    public static boolean isQUICInitial(byte[] payload, int length) {
        if (length < 5) return false;
        // QUIC long header form bit (bit 7) is set
        return (payload[0] & 0x80) != 0;
    }

    public static Optional<String> extract(byte[] payload, int length) {
        if (!isQUICInitial(payload, length)) {
            return Optional.empty();
        }

        // Search for TLS Client Hello handshake type (0x01)
        // Ensure i >= 5 to prevent out of bounds
        for (int i = 5; i + 50 < length; i++) {
            if ((payload[i] & 0xFF) == 0x01) {
                int start = i - 5;
                byte[] subPayload = new byte[length - start];
                System.arraycopy(payload, start, subPayload, 0, subPayload.length);
                Optional<String> sni = TlsSniExtractor.extract(subPayload, subPayload.length);
                if (sni.isPresent()) {
                    return sni;
                }
            }
        }

        return Optional.empty();
    }
}
