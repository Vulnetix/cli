package com.acme.bank;

public class Counter {
    private final Object lock = new Object();
    private int n;

    public synchronized void inc() {
        n++;
    }

    public int get() {
        synchronized (lock) {
            return n;
        }
    }

    public void reset() {
        synchronized (this) {
            n = 0;
        }
    }
}
