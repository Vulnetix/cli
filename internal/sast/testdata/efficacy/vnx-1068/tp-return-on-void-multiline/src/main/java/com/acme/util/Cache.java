package com.acme.util;

import java.util.Map;

public class Cache {
    /**
     * Stores a value.
     * @param key the key
     * @param value the value
     * @return the previous value, or null
     */
    @Override
~>    public synchronized void put(final String key,
                                 Map<String, Integer> value) {
    }

    /** @param ttl seconds to keep the entry */
~>    void expire() {}
}
