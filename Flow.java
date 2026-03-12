package com.dpi.model;

/**
 * Tracks the state of a single network flow (connection).
 * Created when the first packet of a 5-tuple is seen.
 */
public class Flow {
    public final FiveTuple tuple;
    public AppType  appType    = AppType.UNKNOWN;
    public String   sni        = "";       // SNI hostname (from TLS) or HTTP Host
    public boolean  blocked    = false;
    public long     packetCount = 0;
    public long     byteCount   = 0;

    public Flow(FiveTuple tuple) {
        this.tuple = tuple;
        // Pre-classify based on port
        this.appType = AppType.fromPort(tuple.dstPort, tuple.protocol);
    }

    @Override
    public String toString() {
        return tuple + " | App=" + appType + " SNI=" + sni +
               " pkts=" + packetCount + " blocked=" + blocked;
    }
}
