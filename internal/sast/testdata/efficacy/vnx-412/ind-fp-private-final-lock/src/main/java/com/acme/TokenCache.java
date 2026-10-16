package com.acme;

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.locks.ReentrantLock;

public class TokenCache {
    private final Object lock = new Object();
    private static final ReentrantLock WRITE_LOCK = new ReentrantLock();
    final ReentrantLock packageLock = new ReentrantLock();
    private final Map<String, String> tokens = new HashMap<>();

    public String get(String key) {
        synchronized (lock) {
            return tokens.get(key);
        }
    }

    public void flush() {
        WRITE_LOCK.lock();
        try {
            tokens.clear();
        } finally {
            WRITE_LOCK.unlock();
        }
    }
}
