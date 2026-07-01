package com.packetanalyzer.protocol;

import com.packetanalyzer.utils.ByteUtils;
import java.nio.charset.StandardCharsets;
import java.util.Optional;

public class TlsSniExtractor {
    private static final int CONTENT_TYPE_HANDSHAKE = 0x16;
    private static final int HANDSHAKE_CLIENT_HELLO = 0x01;
    private static final int EXTENSION_SNI = 0x0000;
    private static final int SNI_TYPE_HOSTNAME = 0x00;

    public static boolean isTLSClientHello(byte[] payload, int length) {
        if (length < 9) return false;

        // Check TLS record header
        if ((payload[0] & 0xFF) != CONTENT_TYPE_HANDSHAKE) return false;

        int version = ByteUtils.readUint16BE(payload, 1);
        if (version < 0x0300 || version > 0x0304) return false;

        int recordLength = ByteUtils.readUint16BE(payload, 3);
        if (recordLength > length - 5) return false;

        // Check handshake header
        if ((payload[5] & 0xFF) != HANDSHAKE_CLIENT_HELLO) return false;

        return true;
    }

    public static Optional<String> extract(byte[] payload, int length) {
        if (!isTLSClientHello(payload, length)) {
            return Optional.empty();
        }

        int offset = 5; // Skip TLS record header

        // Skip handshake header: type (1 byte), length (3 bytes)
        offset += 4;

        // Client Hello body: client version (2 bytes), random (32 bytes)
        offset += 2 + 32;

        // Session ID
        if (offset >= length) return Optional.empty();
        int sessionIdLength = payload[offset] & 0xFF;
        offset += 1 + sessionIdLength;

        // Cipher suites
        if (offset + 2 > length) return Optional.empty();
        int cipherSuitesLength = ByteUtils.readUint16BE(payload, offset);
        offset += 2 + cipherSuitesLength;

        // Compression methods
        if (offset >= length) return Optional.empty();
        int compressionMethodsLength = payload[offset] & 0xFF;
        offset += 1 + compressionMethodsLength;

        // Extensions
        if (offset + 2 > length) return Optional.empty();
        int extensionsLength = ByteUtils.readUint16BE(payload, offset);
        offset += 2;

        int extensionsEnd = offset + extensionsLength;
        if (extensionsEnd > length) {
            extensionsEnd = length; // Truncated
        }

        while (offset + 4 <= extensionsEnd) {
            int extensionType = ByteUtils.readUint16BE(payload, offset);
            int extensionLength = ByteUtils.readUint16BE(payload, offset + 2);
            offset += 4;

            if (offset + extensionLength > extensionsEnd) break;

            if (extensionType == EXTENSION_SNI) {
                if (extensionLength < 5) break;

                int sniListLength = ByteUtils.readUint16BE(payload, offset);
                if (sniListLength < 3) break;

                int sniType = payload[offset + 2] & 0xFF;
                int sniLength = ByteUtils.readUint16BE(payload, offset + 3);

                if (sniType != SNI_TYPE_HOSTNAME) break;
                if (sniLength > extensionLength - 5) break;

                String sni = new String(payload, offset + 5, sniLength, StandardCharsets.US_ASCII);
                return Optional.of(sni);
            }

            offset += extensionLength;
        }

        return Optional.empty();
    }
}
