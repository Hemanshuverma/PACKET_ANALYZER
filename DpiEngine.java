package com.dpi.engine;

import com.dpi.model.*;
import com.dpi.parser.PacketParser;
import com.dpi.pcap.PcapReader;
import com.dpi.pcap.PcapWriter;
import com.dpi.rules.RuleManager;
import com.dpi.sni.HTTPHostExtractor;
import com.dpi.sni.SNIExtractor;

import java.io.IOException;
import java.util.*;

/**
 * Single-threaded DPI Engine.
 *
 * Equivalent to the C++ main_working.cpp / simple version.
 *
 * Processing pipeline per packet:
 *   1. Read raw bytes from PCAP
 *   2. Parse Ethernet → IP → TCP/UDP headers
 *   3. Build 5-tuple, look up / create Flow
 *   4. Extract SNI (TLS) or Host (HTTP) → classify App
 *   5. Apply blocking rules
 *   6. Forward or drop; write forwarded packets to output PCAP
 *   7. Print final report
 */
public class DpiEngine {

    private final RuleManager       rules;
    private final ConnectionTracker tracker = new ConnectionTracker();
    private final Stats             stats   = new Stats();

    // Domains seen (SNI / Host), for the report
    private final Map<String, AppType> detectedDomains = new LinkedHashMap<>();

    public DpiEngine(RuleManager rules) {
        this.rules = rules;
    }

    /**
     * Process a PCAP file and write filtered output.
     *
     * @param inputPath   Path to the source PCAP
     * @param outputPath  Path to write filtered PCAP
     * @throws IOException on I/O error
     */
    public void process(String inputPath, String outputPath) throws IOException {

        System.out.println("[Reader] Processing packets from: " + inputPath);

        try (PcapReader reader = new PcapReader();
             PcapWriter writer = new PcapWriter()) {

            reader.open(inputPath);
            writer.open(outputPath);

            RawPacket raw;
            while ((raw = reader.readNextPacket()) != null) {
                processPacket(raw, writer);
            }
        }

        System.out.println("[Reader] Done reading " + stats.totalPackets.get() + " packets\n");
        printReport();
    }

    // ── Per-packet processing ────────────────────────────────────────────────

    private void processPacket(RawPacket raw, PcapWriter writer) throws IOException {

        stats.totalPackets.incrementAndGet();
        stats.totalBytes.addAndGet(raw.data.length);

        // Step 1: Parse headers
        ParsedPacket pkt = PacketParser.parse(raw);
        if (pkt == null || pkt.etherType != 0x0800) {
            // Not IPv4 — forward unchanged
            writer.writePacket(raw);
            stats.forwarded.incrementAndGet();
            return;
        }

        if (pkt.hasTcp)      stats.tcpPackets.incrementAndGet();
        else if (pkt.hasUdp) stats.udpPackets.incrementAndGet();

        // Step 2: Build 5-tuple and look up Flow
        FiveTuple tuple = pkt.toFiveTuple();
        Flow flow = tracker.getOrCreate(tuple);
        flow.packetCount++;
        flow.byteCount += raw.data.length;

        // Step 3: Deep packet inspection — try to identify the application
        //         only if we haven't identified it yet
        if (flow.appType == AppType.UNKNOWN ||
            flow.appType == AppType.HTTPS   ||
            flow.appType == AppType.HTTP) {

            inspectPayload(pkt, flow);
        }

        // Step 4: Update flow blocked status
        if (!flow.blocked) {
            flow.blocked = rules.isBlocked(pkt.srcIp, flow.appType, flow.sni);
        }

        // Step 5: Forward or drop
        stats.recordApp(flow.appType);

        if (flow.blocked) {
            stats.dropped.incrementAndGet();
            // Packet is simply not written → dropped
        } else {
            stats.forwarded.incrementAndGet();
            writer.writePacket(raw);
        }
    }

    /** Run DPI on the payload to extract SNI / Host and classify the flow. */
    private void inspectPayload(ParsedPacket pkt, Flow flow) {

        if (pkt.payloadLength <= 0) return;

        byte[] data    = pkt.rawData;
        int    offset  = pkt.payloadOffset;
        int    length  = pkt.payloadLength;

        // TLS → SNI extraction (port 443, TCP)
        if (pkt.hasTcp && pkt.dstPort == 443) {
            Optional<String> sni = SNIExtractor.extract(data, offset, length);
            if (sni.isPresent()) {
                flow.sni     = sni.get();
                flow.appType = AppType.fromSni(flow.sni);
                detectedDomains.put(flow.sni, flow.appType);
                return;
            }
        }

        // HTTP → Host header extraction
        if (pkt.hasTcp && pkt.dstPort == 80) {
            Optional<String> host = HTTPHostExtractor.extract(data, offset, length);
            if (host.isPresent()) {
                flow.sni     = host.get();
                flow.appType = AppType.fromSni(flow.sni);
                if (flow.appType == AppType.HTTPS) flow.appType = AppType.HTTP;
                detectedDomains.put(flow.sni, flow.appType);
            }
        }
    }

    // ── Report ───────────────────────────────────────────────────────────────

    private void printReport() {
        long total = stats.totalPackets.get();
        String line = "═".repeat(62);

        System.out.println("╔" + line + "╗");
        System.out.println("║" + center("PROCESSING REPORT", 62) + "║");
        System.out.println("╠" + line + "╣");
        printRow("Total Packets",  String.valueOf(total));
        printRow("Total Bytes",    String.valueOf(stats.totalBytes.get()));
        printRow("TCP Packets",    String.valueOf(stats.tcpPackets.get()));
        printRow("UDP Packets",    String.valueOf(stats.udpPackets.get()));
        System.out.println("╠" + line + "╣");
        printRow("Forwarded", String.valueOf(stats.forwarded.get()));
        printRow("Dropped",   String.valueOf(stats.dropped.get()));
        System.out.println("╠" + line + "╣");
        System.out.println("║" + center("APPLICATION BREAKDOWN", 62) + "║");
        System.out.println("╠" + line + "╣");

        // Sort by count descending
        stats.getAppCounts().entrySet().stream()
            .sorted((a, b) -> Long.compare(b.getValue().get(), a.getValue().get()))
            .forEach(e -> {
                AppType app   = e.getKey();
                long    count = e.getValue().get();
                double  pct   = total == 0 ? 0.0 : (count * 100.0 / total);
                int     bars  = (int)(pct / 5);
                String  bar   = "#".repeat(Math.max(0, bars));
                boolean blocked = rules.getBlockedApps().contains(app);
                String  label = String.format("%-14s %5d %5.1f%% %-12s%s",
                        app, count, pct, bar, blocked ? " (BLOCKED)" : "");
                System.out.println("║  " + padRight(label, 60) + "║");
            });

        System.out.println("╠" + line + "╣");
        System.out.println("║" + center("DETECTED DOMAINS / SNIs", 62) + "║");
        System.out.println("╠" + line + "╣");

        if (detectedDomains.isEmpty()) {
            System.out.println("║  " + padRight("(none)", 60) + "║");
        } else {
            detectedDomains.forEach((domain, app) -> {
                String row = "  - " + domain + " -> " + app;
                System.out.println("║" + padRight(row, 62) + "║");
            });
        }

        System.out.println("╚" + line + "╝");
    }

    private static void printRow(String label, String value) {
        String row = String.format(" %-38s%22s", label + ":", value);
        System.out.println("║" + row + "║");
    }

    private static String center(String s, int width) {
        int pad = (width - s.length()) / 2;
        String left  = " ".repeat(Math.max(0, pad));
        String right = " ".repeat(Math.max(0, width - s.length() - pad));
        return left + s + right;
    }

    private static String padRight(String s, int width) {
        if (s.length() >= width) return s.substring(0, width);
        return s + " ".repeat(width - s.length());
    }
}
