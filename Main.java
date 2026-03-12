package com.dpi;

import com.dpi.engine.DpiEngine;
import com.dpi.engine.MultiThreadedDpiEngine;
import com.dpi.model.AppType;
import com.dpi.rules.RuleManager;

/**
 * DPI Engine — Main entry point.
 *
 * Usage:
 *   java -jar dpi_engine.jar <input.pcap> <output.pcap> [options]
 *
 * Options:
 *   --block-app  <AppName>   Block all traffic identified as an application
 *                            e.g. --block-app YouTube --block-app TikTok
 *   --block-ip   <x.x.x.x>  Block all traffic from a source IP
 *   --block-domain <pattern> Block any SNI/Host containing pattern
 *   --lbs  <N>               Number of Load Balancer threads (default: 2)
 *   --fps  <N>               Fast Path threads per LB (default: 2)
 *   --single                 Force single-threaded mode
 *
 * Examples:
 *   java -jar dpi_engine.jar capture.pcap out.pcap
 *   java -jar dpi_engine.jar capture.pcap out.pcap --block-app YouTube
 *   java -jar dpi_engine.jar capture.pcap out.pcap --lbs 4 --fps 4
 *   java -jar dpi_engine.jar capture.pcap out.pcap --single
 */
public class Main {

    public static void main(String[] args) throws Exception {

        if (args.length < 2) {
            printUsage();
            System.exit(1);
        }

        String inputPath  = args[0];
        String outputPath = args[1];

        RuleManager rules       = new RuleManager();
        int         numLbs      = 2;
        int         numFps      = 2;
        boolean     singleThread = false;

        // Parse optional arguments
        for (int i = 2; i < args.length; i++) {
            switch (args[i]) {
                case "--block-app" -> {
                    if (i + 1 < args.length) {
                        String appName = args[++i].toUpperCase();
                        try {
                            rules.blockApp(AppType.valueOf(appName));
                        } catch (IllegalArgumentException e) {
                            System.err.println("Unknown app: " + appName +
                                               ". Valid values: " + validApps());
                        }
                    }
                }
                case "--block-ip" -> {
                    if (i + 1 < args.length) rules.blockIp(args[++i]);
                }
                case "--block-domain" -> {
                    if (i + 1 < args.length) rules.blockDomain(args[++i]);
                }
                case "--lbs" -> {
                    if (i + 1 < args.length) numLbs = Integer.parseInt(args[++i]);
                }
                case "--fps" -> {
                    if (i + 1 < args.length) numFps = Integer.parseInt(args[++i]);
                }
                case "--single" -> singleThread = true;
                default -> System.err.println("Unknown option: " + args[i]);
            }
        }

        System.out.println();

        if (singleThread) {
            System.out.println("[Mode] Single-threaded");
            DpiEngine engine = new DpiEngine(rules);
            engine.process(inputPath, outputPath);
        } else {
            System.out.println("[Mode] Multi-threaded (LBs=" + numLbs + ", FPs/LB=" + numFps + ")");
            MultiThreadedDpiEngine engine = new MultiThreadedDpiEngine(rules, numLbs, numFps);
            engine.process(inputPath, outputPath);
        }

        System.out.println("\n[Done] Output written to: " + outputPath);
    }

    private static void printUsage() {
        System.out.println("DPI Engine — Deep Packet Inspection");
        System.out.println();
        System.out.println("Usage: java -jar dpi_engine.jar <input.pcap> <output.pcap> [options]");
        System.out.println();
        System.out.println("Options:");
        System.out.println("  --block-app  <APP>    Block app (e.g. YOUTUBE, TIKTOK, FACEBOOK)");
        System.out.println("  --block-ip   <IP>     Block source IP (e.g. 192.168.1.50)");
        System.out.println("  --block-domain <PAT>  Block SNI containing pattern");
        System.out.println("  --lbs  <N>            Load balancer thread count (default 2)");
        System.out.println("  --fps  <N>            Fast path threads per LB (default 2)");
        System.out.println("  --single              Run in single-threaded mode");
        System.out.println();
        System.out.println("Valid apps: " + validApps());
    }

    private static String validApps() {
        StringBuilder sb = new StringBuilder();
        for (AppType t : AppType.values()) {
            if (sb.length() > 0) sb.append(", ");
            sb.append(t.name());
        }
        return sb.toString();
    }
}
