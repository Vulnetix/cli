package com.acme.cache;

public class Counter {
    private final Object lock = new Object();
    private int count;

    public void inc() {
        synchronized (lock) { count++; }
    }

    public int get() {
        synchronized (lock) {
            // read under the lock
            return count;
        }
    }

    public synchronized void reset() {}

    public static synchronized void noop() {
    }
}
