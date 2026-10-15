package com.acme;

import java.util.HashMap;
import java.util.Map;

public class Counts {
    private final Map<String, Integer> counts = new HashMap<>();

    public void purgeZero() {
        for (String key : counts.keySet()) {
            if (counts.get(key) == 0) {
~>                counts.remove(key);
            }
        }
    }

    public void track(String name) {
        for (final Map.Entry<String, Integer> e : this.counts.entrySet()) {
~>            this.counts.put(name + e.getKey(), 0);
        }
    }
}
