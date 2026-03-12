package com.dpi.engine;

import com.dpi.model.Flow;
import com.dpi.model.FiveTuple;

import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

/**
 * Tracks active network flows using a 5-tuple as the key.
 *
 * When the first packet of a connection arrives, a new Flow is created.
 * All subsequent packets with the same 5-tuple update the existing flow.
 *
 * This is NOT thread-safe — intended for use within a single processing thread.
 */
public class ConnectionTracker {

    private final Map<FiveTuple, Flow> flows = new HashMap<>();

    /**
     * Look up or create a Flow for the given 5-tuple.
     *
     * @param tuple  The 5-tuple identifying this connection
     * @return       The existing or newly created Flow
     */
    public Flow getOrCreate(FiveTuple tuple) {
        return flows.computeIfAbsent(tuple, Flow::new);
    }

    /**
     * Look up a flow without creating one.
     *
     * @return Flow, or null if not tracked yet
     */
    public Flow get(FiveTuple tuple) {
        return flows.get(tuple);
    }

    public Collection<Flow> getAllFlows() {
        return flows.values();
    }

    public int getFlowCount() {
        return flows.size();
    }
}
