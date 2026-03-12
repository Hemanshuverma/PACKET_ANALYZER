package com.dpi.rules;

import com.dpi.model.AppType;

import java.util.HashSet;
import java.util.Set;

/**
 * Manages the set of active blocking rules.
 *
 * Three types of rules:
 *   1. Blocked source IPs   — drop all traffic from a specific IP
 *   2. Blocked applications — drop all traffic identified as a certain app
 *   3. Blocked domains      — drop if SNI contains the pattern (substring match)
 */
public class RuleManager {

    private final Set<Long>     blockedIps     = new HashSet<>();
    private final Set<AppType>  blockedApps    = new HashSet<>();
    private final Set<String>   blockedDomains = new HashSet<>();

    // ── Rule builders ────────────────────────────────────────────────────────

    /**
     * Block all packets from a source IP (dotted-decimal notation).
     */
    public void blockIp(String ip) {
        blockedIps.add(parseIp(ip));
        System.out.println("[Rules] Blocked IP: " + ip);
    }

    /**
     * Block all traffic identified as a particular application.
     */
    public void blockApp(AppType app) {
        blockedApps.add(app);
        System.out.println("[Rules] Blocked app: " + app);
    }

    /**
     * Block all traffic whose SNI contains the given substring.
     */
    public void blockDomain(String pattern) {
        blockedDomains.add(pattern.toLowerCase());
        System.out.println("[Rules] Blocked domain pattern: " + pattern);
    }

    // ── Decision ─────────────────────────────────────────────────────────────

    /**
     * Returns true if the packet/flow should be dropped.
     *
     * @param srcIp   Source IP as unsigned 32-bit in long
     * @param app     Identified application type
     * @param sni     SNI / Host header value (empty string if unknown)
     */
    public boolean isBlocked(long srcIp, AppType app, String sni) {
        if (blockedIps.contains(srcIp))   return true;
        if (blockedApps.contains(app))    return true;

        if (sni != null && !sni.isEmpty()) {
            String lower = sni.toLowerCase();
            for (String pattern : blockedDomains) {
                if (lower.contains(pattern)) return true;
            }
        }

        return false;
    }

    // ── Helpers ──────────────────────────────────────────────────────────────

    private static long parseIp(String ip) {
        String[] parts = ip.split("\\.");
        if (parts.length != 4) throw new IllegalArgumentException("Invalid IP: " + ip);
        long result = 0;
        for (String p : parts) {
            result = (result << 8) | (Integer.parseInt(p) & 0xFF);
        }
        return result;
    }

    public Set<Long>    getBlockedIps()     { return blockedIps; }
    public Set<AppType> getBlockedApps()    { return blockedApps; }
    public Set<String>  getBlockedDomains() { return blockedDomains; }
}
