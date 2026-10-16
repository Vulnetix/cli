package com.acme.stats;

import java.util.HashMap;
import java.util.Map;

public class Counter {
    private final Map<String, Long> totals = new HashMap<>();

    public void add(String key, long v) {
~>        Long boxed = new Long(v);
        totals.merge(key, boxed, Long::sum);
    }
}
