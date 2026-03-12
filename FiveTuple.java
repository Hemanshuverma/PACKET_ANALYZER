package com.dpi.model;

import java.util.Objects;

/**
 * Uniquely identifies a network flow / connection.
 * All packets sharing the same 5-tuple belong to the same flow.
 */
public final class FiveTuple {
    public final long   srcIp;    // stored as unsigned 32-bit in a long
    public final long   dstIp;
    public final int    srcPort;  // 0-65535
    public final int    dstPort;
    public final int    protocol; // 6=TCP, 17=UDP

    public FiveTuple(long srcIp, long dstIp, int srcPort, int dstPort, int protocol) {
        this.srcIp    = srcIp;
        this.dstIp    = dstIp;
        this.srcPort  = srcPort;
        this.dstPort  = dstPort;
        this.protocol = protocol;
    }

    /** Format an IP stored as unsigned 32-bit long to dotted-decimal. */
    public static String ipToString(long ip) {
        return ((ip >> 24) & 0xFF) + "." +
               ((ip >> 16) & 0xFF) + "." +
               ((ip >>  8) & 0xFF) + "." +
               ( ip        & 0xFF);
    }

    public String getSrcIpString() { return ipToString(srcIp); }
    public String getDstIpString() { return ipToString(dstIp); }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof FiveTuple)) return false;
        FiveTuple t = (FiveTuple) o;
        return srcIp == t.srcIp && dstIp == t.dstIp &&
               srcPort == t.srcPort && dstPort == t.dstPort &&
               protocol == t.protocol;
    }

    @Override
    public int hashCode() {
        return Objects.hash(srcIp, dstIp, srcPort, dstPort, protocol);
    }

    @Override
    public String toString() {
        String proto = (protocol == 6) ? "TCP" : (protocol == 17 ? "UDP" : "P" + protocol);
        return proto + " " + getSrcIpString() + ":" + srcPort +
               " -> " + getDstIpString() + ":" + dstPort;
    }
}
