package com.acme;

public class Retry {
    public void spin(java.util.concurrent.atomic.AtomicBoolean ready) {
        while (!ready.get()) {
            // busy-wait: ready flips within microseconds, see benchmark notes
        }
        if (ready.get()) { /* nothing more to do */ }
    }
}
