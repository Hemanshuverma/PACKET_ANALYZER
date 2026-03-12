package com.dpi.sni;

import java.nio.charset.StandardCharsets;
import java.util.Optional;

/**
 * Extracts the Host header from plain HTTP/1.x requests.
 *
 * HTTP request format:
 *   GET /path HTTP/1.1\r\n
 *   Host: www.example.com\r\n
 *   ...
 */
public class HTTPHostExtractor {

    private static final byte[] HTTP_METHODS[] = {
        "GET ".getBytes(StandardCharsets.US_ASCII),
        "POST ".getBytes(StandardCharsets.US_ASCII),
        "HEAD ".getBytes(StandardCharsets.US_ASCII),
        "PUT ".getBytes(StandardCharsets.US_ASCII),
        "DELETE ".getBytes(StandardCharsets.US_ASCII),
        "OPTIONS ".getBytes(StandardCharsets.US_ASCII),
        "PATCH ".getBytes(StandardCharsets.US_ASCII)
    };

    private static final byte[] HOST_HEADER = "Host: ".getBytes(StandardCharsets.US_ASCII);

    /**
     * Attempt to extract the HTTP Host header value.
     *
     * @param payload Raw TCP payload bytes
     * @param offset  Start of payload within the array
     * @param length  Bytes of payload
     * @return        Optional hostname (without port suffix)
     */
    public static Optional<String> extract(byte[] payload, int offset, int length) {
        if (length < 16) return Optional.empty();

        // Check that it starts with an HTTP method
        boolean isHttp = false;
        for (byte[] method : HTTP_METHODS) {
            if (startsWith(payload, offset, length, method)) {
                isHttp = true;
                break;
            }
        }
        if (!isHttp) return Optional.empty();

        // Search for "Host: " header (case-insensitive search simplified to exact match)
        String text = new String(payload, offset, length, StandardCharsets.US_ASCII);
        int hostIdx = findCaseInsensitive(text, "host: ");
        if (hostIdx < 0) return Optional.empty();

        int valueStart = hostIdx + 6;  // length of "host: "
        int valueEnd   = text.indexOf('\r', valueStart);
        if (valueEnd < 0) valueEnd = text.indexOf('\n', valueStart);
        if (valueEnd < 0) valueEnd = text.length();

        String host = text.substring(valueStart, valueEnd).trim();

        // Strip port if present (e.g., "example.com:8080" → "example.com")
        int colonIdx = host.indexOf(':');
        if (colonIdx >= 0) host = host.substring(0, colonIdx);

        return host.isEmpty() ? Optional.empty() : Optional.of(host);
    }

    private static boolean startsWith(byte[] data, int offset, int length, byte[] prefix) {
        if (length < prefix.length) return false;
        for (int i = 0; i < prefix.length; i++) {
            if (data[offset + i] != prefix[i]) return false;
        }
        return true;
    }

    private static int findCaseInsensitive(String text, String pattern) {
        return text.toLowerCase().indexOf(pattern.toLowerCase());
    }
}
