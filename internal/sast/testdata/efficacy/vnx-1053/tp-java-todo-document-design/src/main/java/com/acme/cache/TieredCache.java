package com.acme.cache;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

~>// TODO: document the design of the eviction tiers before anyone else touches this
public class TieredCache {
    private final Map<String, byte[]> hot = new ConcurrentHashMap<>();

    /*
~>     * FIXME explain the architecture: who owns invalidation, L1 or L2?
     */
    public byte[] get(String key) {
~>        return hot.get(key); // XXX design rationale not written down anywhere
    }
}
