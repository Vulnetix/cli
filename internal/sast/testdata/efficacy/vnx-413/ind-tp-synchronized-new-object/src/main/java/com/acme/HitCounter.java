package com.acme;

import java.util.HashMap;
import java.util.Map;

public class HitCounter {
    private final Map<String, Integer> hits = new HashMap<>();

    public void record(String path) {
~>        synchronized (new Object()) {
            hits.merge(path, 1, Integer::sum);
        }
    }
}
