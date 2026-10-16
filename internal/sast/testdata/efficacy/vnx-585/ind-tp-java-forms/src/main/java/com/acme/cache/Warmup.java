package com.acme.cache;

public class Warmup {
    private final Object lock = new Object();
    private static final Object MUTEX = new Object();
    private int hits;

    public void barrier() {
~>        synchronized (lock) {}
    }

    public void waitForInit() {
~>        synchronized (MUTEX) {
        }
    }

    public void flush() {
~>        synchronized (this)
        {
            // TODO: move the flush back under the lock

        }
        hits = 0;
    }
}
