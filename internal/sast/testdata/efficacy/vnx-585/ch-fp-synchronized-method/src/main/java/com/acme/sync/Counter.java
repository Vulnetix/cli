package com.acme.sync;

import java.util.Collections;
import java.util.List;

public class Counter {
    private int n;
    private final List<String> names = Collections.synchronizedList(new java.util.ArrayList<>());

    public synchronized void reset() {}

    public synchronized void inc() { n++; }

    void notifyAllWaiters() {
        synchronized (this) {
            notifyAll();
        }
    }
}
