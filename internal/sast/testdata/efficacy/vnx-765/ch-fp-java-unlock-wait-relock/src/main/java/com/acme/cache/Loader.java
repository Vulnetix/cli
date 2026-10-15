package com.acme.cache;

import java.util.concurrent.locks.ReentrantLock;

public class Loader {
    private final ReentrantLock lock = new ReentrantLock();
    private String value;

    public String load() {
        lock.lock();
        try {
            if (value == null) {
                lock.unlock();
                String fetched = fetch();
                lock.lock();
                value = fetched;
            }
            return value;
        } finally {
            lock.unlock();
        }
    }

    public void twoPhases() {
        lock.lock();
        try { value = null; } finally { lock.unlock(); }
        lock.lock();
        try { value = ""; } finally { lock.unlock(); }
    }

    private String fetch() {
        return "x";
    }
}
