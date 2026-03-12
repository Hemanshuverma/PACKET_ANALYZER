package com.dpi.engine;

import com.dpi.model.*;
import com.dpi.parser.PacketParser;
import com.dpi.pcap.PcapReader;
import com.dpi.pcap.PcapWriter;
import com.dpi.rules.RuleManager;
import com.dpi.util.ThreadSafeQueue;

import java.io.IOException;
import java.util.*;
import java.util.concurrent.atomic.AtomicLong;
import java.util.stream.Collectors;

/**
 * Multi-threaded DPI Engine.
 *
 * Architecture:
 *
 *   Reader (main thread)
 *       └─► LB0 queue
 *       └─► LB1 queue
 *             ↓ (per LB)
 *           LB thread  →  FP0 queue
 *                      →  FP1 queue
 *                            ↓ (per FP)
 *                          FP thread  →  Output queue
 *                                            ↓
 *                                       Writer thread  →  output.pcap
 *
 * Equivalent to dpi_mt.cpp.
 *
 * Configuration:
 *   numLbs  — number of Load Balancer threads (default 2)
 *   numFps  — number of Fast Path threads PER LB (default 2, so 4 total)
 */
public class MultiThreadedDpiEngine {

    // Queue capacities
    private static final int LB_QUEUE_CAPACITY  = 4096;
    private static final int FP_QUEUE_CAPACITY  = 4096;
    private static final int OUT_QUEUE_CAPACITY = 8192;

    private final RuleManager rules;
    private final int         numLbs;
    private final int         numFpsPerLb;

    public MultiThreadedDpiEngine(RuleManager rules, int numLbs, int numFpsPerLb) {
        this.rules       = rules;
        this.numLbs      = numLbs;
        this.numFpsPerLb = numFpsPerLb;
    }

    /**
     * Process input PCAP and write filtered output.
     */
    public void process(String inputPath, String outputPath) throws IOException, InterruptedException {

        System.out.println("╔" + "═".repeat(62) + "╗");
        System.out.println("║" + center("DPI ENGINE v2.0 (Multi-threaded)", 62) + "║");
        System.out.println("╠" + "═".repeat(62) + "╣");
        System.out.printf( "║  Load Balancers: %2d    FPs per LB: %2d    Total FPs: %3d%8s║%n",
                           numLbs, numFpsPerLb, numLbs * numFpsPerLb, "");
        System.out.println("╚" + "═".repeat(62) + "╝\n");

        // ── Create queues ────────────────────────────────────────────────────

        // One input queue per LB
        List<ThreadSafeQueue<ParsedPacket>> lbQueues = new ArrayList<>();
        for (int i = 0; i < numLbs; i++) {
            lbQueues.add(new ThreadSafeQueue<>(LB_QUEUE_CAPACITY));
        }

        // For each LB, one queue per FP
        List<List<ThreadSafeQueue<ParsedPacket>>> fpQueueSets = new ArrayList<>();
        for (int lb = 0; lb < numLbs; lb++) {
            List<ThreadSafeQueue<ParsedPacket>> fpqs = new ArrayList<>();
            for (int fp = 0; fp < numFpsPerLb; fp++) {
                fpqs.add(new ThreadSafeQueue<>(FP_QUEUE_CAPACITY));
            }
            fpQueueSets.add(fpqs);
        }

        // Single output queue
        ThreadSafeQueue<RawPacket> outputQueue = new ThreadSafeQueue<>(OUT_QUEUE_CAPACITY);

        // ── Create workers ───────────────────────────────────────────────────

        List<LoadBalancer> lbs  = new ArrayList<>();
        List<FastPath>     fps  = new ArrayList<>();
        List<Thread>       threads = new ArrayList<>();

        // LB threads
        for (int i = 0; i < numLbs; i++) {
            LoadBalancer lb = new LoadBalancer(i, lbQueues.get(i), fpQueueSets.get(i));
            lbs.add(lb);
            threads.add(new Thread(lb, "LB-" + i));
        }

        // FP threads
        int fpId = 0;
        for (int lb = 0; lb < numLbs; lb++) {
            for (int fp = 0; fp < numFpsPerLb; fp++) {
                FastPath fastPath = new FastPath(
                        fpId,
                        fpQueueSets.get(lb).get(fp),
                        outputQueue,
                        rules);
                fps.add(fastPath);
                threads.add(new Thread(fastPath, "FP-" + fpId));
                fpId++;
            }
        }

        // Output writer thread
        AtomicLong writtenCount = new AtomicLong();
        Thread writerThread = new Thread(() -> {
            try (PcapWriter writer = new PcapWriter()) {
                writer.open(outputPath);
                RawPacket pkt;
                while ((pkt = outputQueue.pop()) != null) {
                    writer.writePacket(pkt);
                    writtenCount.incrementAndGet();
                }
            } catch (IOException | InterruptedException e) {
                System.err.println("[Writer] Error: " + e.getMessage());
            }
        }, "Writer");

        // ── Start all threads ────────────────────────────────────────────────

        threads.forEach(Thread::start);
        writerThread.start();

        // ── Reader (main thread) ─────────────────────────────────────────────

        System.out.println("[Reader] Processing packets from: " + inputPath);
        long totalRead = 0;
        long tcpCount  = 0;
        long udpCount  = 0;
        long totalBytes = 0;

        try (PcapReader reader = new PcapReader()) {
            reader.open(inputPath);
            RawPacket raw;
            while ((raw = reader.readNextPacket()) != null) {
                totalRead++;
                totalBytes += raw.data.length;

                ParsedPacket pkt = PacketParser.parse(raw);
                if (pkt == null) {
                    // Can't parse — forward directly to output
                    outputQueue.push(raw);
                    continue;
                }

                if (pkt.hasTcp)      tcpCount++;
                else if (pkt.hasUdp) udpCount++;

                // Route to an LB using hash of 5-tuple
                int lbIdx = Math.floorMod(pkt.toFiveTuple().hashCode(), numLbs);
                lbQueues.get(lbIdx).push(pkt);
            }
        }

        System.out.println("[Reader] Done reading " + totalRead + " packets");

        // Signal LBs that reading is done
        lbQueues.forEach(ThreadSafeQueue::close);

        // Wait for LBs then FPs
        for (Thread t : threads) t.join();

        // Signal writer that all FPs are done
        outputQueue.close();
        writerThread.join();

        // ── Final report ─────────────────────────────────────────────────────

        printReport(totalRead, totalBytes, tcpCount, udpCount,
                    writtenCount.get(), lbs, fps);
    }

    // ── Report ───────────────────────────────────────────────────────────────

    private void printReport(long total, long totalBytes, long tcpCount, long udpCount,
                              long forwarded, List<LoadBalancer> lbs, List<FastPath> fps) {

        long dropped = total - forwarded;
        String line = "═".repeat(62);

        System.out.println("\n╔" + line + "╗");
        System.out.println("║" + center("PROCESSING REPORT", 62) + "║");
        System.out.println("╠" + line + "╣");
        printRow("Total Packets", String.valueOf(total));
        printRow("Total Bytes",   String.valueOf(totalBytes));
        printRow("TCP Packets",   String.valueOf(tcpCount));
        printRow("UDP Packets",   String.valueOf(udpCount));
        System.out.println("╠" + line + "╣");
        printRow("Forwarded", String.valueOf(forwarded));
        printRow("Dropped",   String.valueOf(dropped));

        // Thread statistics
        System.out.println("╠" + line + "╣");
        System.out.println("║" + center("THREAD STATISTICS", 62) + "║");
        System.out.println("╠" + line + "╣");
        lbs.forEach(lb -> printRow("LB" + lb.getId() + " dispatched", String.valueOf(lb.getDispatched())));
        fps.forEach(fp -> printRow("FP" + fp.getId() + " processed",  String.valueOf(fp.getProcessed())));

        // Application breakdown (aggregate across all FPs)
        Map<AppType, Long> appTotals = new TreeMap<>();
        fps.forEach(fp -> fp.getTracker().getAllFlows().forEach(flow -> {
            appTotals.merge(flow.appType, flow.packetCount, Long::sum);
        }));

        System.out.println("╠" + line + "╣");
        System.out.println("║" + center("APPLICATION BREAKDOWN", 62) + "║");
        System.out.println("╠" + line + "╣");

        appTotals.entrySet().stream()
            .sorted((a, b) -> Long.compare(b.getValue(), a.getValue()))
            .forEach(e -> {
                AppType app   = e.getKey();
                long    count = e.getValue();
                double  pct   = total == 0 ? 0.0 : (count * 100.0 / total);
                int     bars  = (int)(pct / 5);
                String  bar   = "#".repeat(Math.max(0, bars));
                boolean blocked = rules.getBlockedApps().contains(app);
                String  label = String.format("%-14s %5d %5.1f%% %-12s%s",
                        app, count, pct, bar, blocked ? " (BLOCKED)" : "");
                System.out.println("║  " + padRight(label, 60) + "║");
            });

        // Detected domains
        System.out.println("╠" + line + "╣");
        System.out.println("║" + center("DETECTED DOMAINS / SNIs", 62) + "║");
        System.out.println("╠" + line + "╣");

        Map<String, AppType> allDomains = new LinkedHashMap<>();
        fps.forEach(fp -> allDomains.putAll(fp.getDetectedDomains()));

        if (allDomains.isEmpty()) {
            System.out.println("║  " + padRight("(none)", 60) + "║");
        } else {
            allDomains.forEach((domain, app) -> {
                String row = "  - " + domain + " -> " + app;
                System.out.println("║" + padRight(row, 62) + "║");
            });
        }

        System.out.println("╚" + line + "╝");
    }

    private static void printRow(String label, String value) {
        System.out.printf("║ %-38s%22s║%n", label + ":", value);
    }

    private static String center(String s, int width) {
        int pad  = (width - s.length()) / 2;
        return " ".repeat(Math.max(0, pad)) + s +
               " ".repeat(Math.max(0, width - s.length() - pad));
    }

    private static String padRight(String s, int width) {
        if (s.length() >= width) return s.substring(0, width);
        return s + " ".repeat(width - s.length());
    }
}
