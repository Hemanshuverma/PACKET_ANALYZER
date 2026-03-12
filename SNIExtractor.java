package com.dpi.sni;

import com.dpi.parser.PacketParser;

import java.nio.charset.StandardCharsets;
import java.util.Optional;

/**
 * Extracts the Server Name Indication (SNI) hostname from TLS Client Hello packets.
 *
 * Even though HTTPS traffic is encrypted, the TLS handshake Client Hello contains
 * the target hostname in plaintext — this is the core of DPI for HTTPS.
 *
 * TLS Record structure:
 *   Byte 0:     Content Type  (0x16 = Handshake)
 *   Bytes 1-2:  Version       (0x0301 = TLS 1.0 record layer)
 *   Bytes 3-4:  Record Length
 *
 * Handshake structure (starts at byte 5):
 *   Byte 0:     Handshake Type (0x01 = Client Hello)
 *   Bytes 1-3:  Length (24-bit big-endian)
 *
 * Client Hello body:
 *   Bytes 0-1:  Client Version
 *   Bytes 2-33: Random (32 bytes)
 *   Byte 34:    Session ID Length (N)
 *   N bytes:    Session ID
 *   2 bytes:    Cipher Suites Length (M)
 *   M bytes:    Cipher Suites
 *   1 byte:     Compression Methods Length (C)
 *   C bytes:    Compression Methods
 *   2 bytes:    Extensions Length
 *   [Extensions]
 *
 * SNI Extension (type 0x0000):
 *   2 bytes:  Extension Type  = 0x0000
 *   2 bytes:  Extension Length
 *   2 bytes:  SNI List Length
 *   1 byte:   Name Type       = 0x00 (host_name)
 *   2 bytes:  Name Length
 *   N bytes:  Hostname (ASCII)
 */
public class SNIExtractor {

    private static final int TLS_HANDSHAKE    = 0x16;
    private static final int TLS_CLIENT_HELLO = 0x01;
    private static final int EXT_SNI          = 0x0000;

    /**
     * Attempt to extract the SNI hostname from a TCP payload.
     *
     * @param payload  Raw TCP payload bytes
     * @param length   Number of valid bytes in payload
     * @return         Optional containing the hostname, or empty if not found
     */
    public static Optional<String> extract(byte[] payload, int offset, int length) {
        // Need at least TLS record header (5) + handshake header (4) + ClientHello basics
        if (length < 43) return Optional.empty();

        // Byte 0: Content Type must be Handshake (0x16)
        if ((payload[offset] & 0xFF) != TLS_HANDSHAKE) return Optional.empty();

        // Skip record-layer version (bytes 1-2) and record length (bytes 3-4)
        // Byte 5: Handshake type must be Client Hello (0x01)
        if ((payload[offset + 5] & 0xFF) != TLS_CLIENT_HELLO) return Optional.empty();

        // Handshake body starts at offset+9 (after TLS record header 5 + handshake header 4)
        int pos = offset + 9;

        // Skip ClientVersion (2 bytes) + Random (32 bytes) = 34 bytes
        pos += 34;
        if (pos >= offset + length) return Optional.empty();

        // Skip Session ID
        int sessionIdLen = payload[pos] & 0xFF;
        pos += 1 + sessionIdLen;
        if (pos + 2 >= offset + length) return Optional.empty();

        // Skip Cipher Suites
        int cipherSuitesLen = PacketParser.readUint16(payload, pos);
        pos += 2 + cipherSuitesLen;
        if (pos + 1 >= offset + length) return Optional.empty();

        // Skip Compression Methods
        int compressionLen = payload[pos] & 0xFF;
        pos += 1 + compressionLen;
        if (pos + 2 >= offset + length) return Optional.empty();

        // Read Extensions length
        int extensionsLen = PacketParser.readUint16(payload, pos);
        pos += 2;

        int extEnd = pos + extensionsLen;
        if (extEnd > offset + length) extEnd = offset + length;

        // Walk through extensions looking for SNI (type 0x0000)
        while (pos + 4 <= extEnd) {
            int extType = PacketParser.readUint16(payload, pos);
            int extLen  = PacketParser.readUint16(payload, pos + 2);
            pos += 4;

            if (extType == EXT_SNI) {
                // SNI Extension data:
                //   2 bytes: SNI list length
                //   1 byte:  SNI entry type (0x00 = host_name)
                //   2 bytes: hostname length
                //   N bytes: hostname
                if (pos + 5 > extEnd) return Optional.empty();

                // skip SNI list length (2) + type byte (1) = 3 bytes
                int nameLen = PacketParser.readUint16(payload, pos + 3);
                int nameOff = pos + 5;

                if (nameOff + nameLen > offset + length) return Optional.empty();

                String sni = new String(payload, nameOff, nameLen, StandardCharsets.US_ASCII);
                return Optional.of(sni);
            }

            pos += extLen;
        }

        return Optional.empty();
    }
}
