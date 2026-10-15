package com.acme.util;

import java.util.Map;
import java.util.HashMap;

public class Buffer {
    private final StringBuilder sb = new StringBuilder();
    private final Map<String, Integer> counts = new HashMap<>();
    private final Object[] stripes = new Object[16];

    void add(String s) {
        synchronized (sb) {
            sb.append(s);
        }
        synchronized (counts) {
            counts.merge(s, 1, Integer::sum);
        }
        synchronized (stripes[s.hashCode() & 15]) {
            sb.append(s);
        }
    }
}
