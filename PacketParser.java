package com.dpi.parser;

import com.dpi.model.ParsedPacket;
import com.dpi.model.RawPacket;

/**
 * Parses raw packet bytes into structured protocol fields.
 *
 * Supported stack:
 *   Ethernet II → IPv4 → TCP / UDP
 *
 * All multi-byte integers in network packets are big-endian.
 */
public class PacketParser {

    private static final int ETH_HEADER_LEN  = 14;
    private static final int IPV4_ETHER_TYPE = 0x0800;
    private static final int PROTO_TCP       = 6;
    private static final int PROTO_UDP       = 17;

    /**
     * Parse a raw packet into a ParsedPacket.
     *
     * @param raw   Bytes from the PCAP file
     * @return      Populated ParsedPacket, or null if parsing fails
     */
    public static ParsedPacket parse(RawPacket raw) {
        byte[] data = raw.data;
        if (data.length < ETH_HEADER_LEN) return null;

        ParsedPacket pkt = new ParsedPacket();
        pkt.rawData = data;
        pkt.raw     = raw;

        // ── Ethernet Header (14 bytes) ───────────────────────────────────────
        pkt.dstMac = formatMac(data, 0);
        pkt.srcMac = formatMac(data, 6);
        pkt.etherType = readUint16(data, 12);

        if (pkt.etherType != IPV4_ETHER_TYPE) {
            return pkt;  // Not IPv4 — return partial parse
        }

        // ── IPv4 Header ──────────────────────────────────────────────────────
        int ipOffset = ETH_HEADER_LEN;
        if (data.length < ipOffset + 20) return pkt;

        int versionIHL  = data[ipOffset] & 0xFF;
        pkt.ipHeaderLen = (versionIHL & 0x0F) * 4;  // IHL field × 4 bytes
        pkt.ttl         = data[ipOffset + 8] & 0xFF;
        pkt.protocol    = data[ipOffset + 9] & 0xFF;
        pkt.srcIp       = readUint32(data, ipOffset + 12);
        pkt.dstIp       = readUint32(data, ipOffset + 16);

        int transportOffset = ipOffset + pkt.ipHeaderLen;
        if (transportOffset >= data.length) return pkt;

        // ── TCP Header ───────────────────────────────────────────────────────
        if (pkt.protocol == PROTO_TCP) {
            if (data.length < transportOffset + 20) return pkt;

            pkt.hasTcp  = true;
            pkt.srcPort = readUint16(data, transportOffset);
            pkt.dstPort = readUint16(data, transportOffset + 2);
            pkt.seqNum  = readUint32(data, transportOffset + 4);
            pkt.ackNum  = readUint32(data, transportOffset + 8);

            int dataOffset = (data[transportOffset + 12] & 0xF0) >> 4;
            pkt.tcpHeaderLen = dataOffset * 4;
            pkt.tcpFlags = data[transportOffset + 13] & 0xFF;

            pkt.payloadOffset = transportOffset + pkt.tcpHeaderLen;
            pkt.payloadLength = data.length - pkt.payloadOffset;
            if (pkt.payloadLength < 0) pkt.payloadLength = 0;
        }

        // ── UDP Header ───────────────────────────────────────────────────────
        else if (pkt.protocol == PROTO_UDP) {
            if (data.length < transportOffset + 8) return pkt;

            pkt.hasUdp  = true;
            pkt.srcPort = readUint16(data, transportOffset);
            pkt.dstPort = readUint16(data, transportOffset + 2);
            // length (2) + checksum (2) — skip
            pkt.payloadOffset = transportOffset + 8;
            pkt.payloadLength = data.length - pkt.payloadOffset;
            if (pkt.payloadLength < 0) pkt.payloadLength = 0;
        }

        return pkt;
    }

    // ── Utility helpers ──────────────────────────────────────────────────────

    /** Read a big-endian unsigned 16-bit integer. */
    public static int readUint16(byte[] data, int offset) {
        return ((data[offset] & 0xFF) << 8) |
               (data[offset + 1] & 0xFF);
    }

    /** Read a big-endian unsigned 32-bit integer into a long. */
    public static long readUint32(byte[] data, int offset) {
        return ((long)(data[offset]     & 0xFF) << 24) |
               ((long)(data[offset + 1] & 0xFF) << 16) |
               ((long)(data[offset + 2] & 0xFF) <<  8) |
               ((long)(data[offset + 3] & 0xFF));
    }

    /** Format 6 bytes at offset as colon-separated MAC address. */
    private static String formatMac(byte[] data, int offset) {
        return String.format("%02X:%02X:%02X:%02X:%02X:%02X",
                data[offset]   & 0xFF, data[offset+1] & 0xFF,
                data[offset+2] & 0xFF, data[offset+3] & 0xFF,
                data[offset+4] & 0xFF, data[offset+5] & 0xFF);
    }
}
