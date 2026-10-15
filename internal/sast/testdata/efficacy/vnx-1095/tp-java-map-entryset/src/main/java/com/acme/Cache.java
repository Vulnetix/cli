package com.acme;

import java.util.HashMap;
import java.util.Map;

public class Cache {
    private final Map<String, Entry> entries = new HashMap<>();

    public void evict(long limit) {
        for (Map.Entry<String, Entry> e : entries.entrySet()) {
            if (e.getValue().size() > limit) {
~>                entries.remove(e.getKey());
            }
        }
        for (String key : entries.keySet()) {
~>            entries.put(key + ".old", entries.get(key));
        }
    }
}
