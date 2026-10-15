package com.acme.sync;

public class Counter {
    private final Object lock = new Object();
    private int count;

    void inc() {
        synchronized (lock) { count++; }
        synchronized (this) {
            count += 2;
        }
        synchronized (lock)
        {
            notifyAll();
        }
    }

    public synchronized void reset() {}
}
