package com.acme;

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.locks.ReentrantLock;

public class Good {
    private final Object lock = new Object();
    private final Map<String, String> map = new HashMap<>();
    private final ReentrantLock rl = new ReentrantLock();
    private static int total;
    private int n;

    public void a() {
        synchronized (lock) { n++; }
        synchronized (this) { n++; }
        synchronized (Good.class) { total++; }
        synchronized (map) { map.put("k", "v"); }
        rl.lock();
        try { n++; } finally { rl.unlock(); }
    }

    public static synchronized void inc() {
        total++;
    }

    public synchronized void local() {
        n++;
    }
}
