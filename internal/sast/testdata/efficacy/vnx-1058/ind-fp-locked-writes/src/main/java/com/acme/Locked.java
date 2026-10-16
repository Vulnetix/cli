package com.acme;

import java.util.*;
import java.util.concurrent.locks.*;
import org.springframework.stereotype.Component;

@Component
public class Locked {
    private static final Object LOCK = new Object();
    private static int total;
    private static Map<String, Integer> reg = new HashMap<>();
    private static final ReentrantLock rl = new ReentrantLock();

    public void add(int n) {
        synchronized (LOCK) {
            total += n;
        }
    }

    public synchronized void register(String k) {
        reg.put(k, 1);
    }

    public void reset() {
        rl.lock();
        try {
            total = 0;
        } finally {
            rl.unlock();
        }
    }
}
