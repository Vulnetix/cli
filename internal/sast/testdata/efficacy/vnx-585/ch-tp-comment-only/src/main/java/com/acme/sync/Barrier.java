package com.acme.sync;

public class Barrier {
    private final Object lock = new Object();

    void await() {
~>        synchronized (lock) { /* wait for writers to drain */ }
    }

    void drain() {
~>        synchronized(this.lock)
        {
            // intentionally empty: memory barrier
        }
    }
}
