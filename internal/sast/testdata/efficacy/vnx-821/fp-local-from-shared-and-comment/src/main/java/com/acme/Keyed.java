package com.acme;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class Keyed {
    private final Map<String, Object> locks = new ConcurrentHashMap<>();

    public void run(String key) {
        Object lock = locks.computeIfAbsent(key, k -> new Object());
        synchronized (lock) {
            work(key);
        }
        // synchronized (new Object()) would protect nothing
        String doc = "synchronized (new Object()) is a bug";
    }

    private void work(String key) {}
}
