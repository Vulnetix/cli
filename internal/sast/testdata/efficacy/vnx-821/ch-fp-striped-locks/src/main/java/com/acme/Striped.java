package com.acme;

import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

public class Striped {
    private final ConcurrentMap<String, Object> locks = new ConcurrentHashMap<>();
    private final Object[] stripes = new Object[16];

    public void update(String key, Runnable r) {
        synchronized (locks.computeIfAbsent(key, k -> new Object())) {
            r.run();
        }
        synchronized (stripes[key.hashCode() & 15]) {
            r.run();
        }
        String msg = "synchronized (new Object()) gives no exclusion";
    }
}
