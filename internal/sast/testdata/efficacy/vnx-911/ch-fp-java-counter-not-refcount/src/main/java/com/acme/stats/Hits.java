package com.acme.stats;

import java.util.concurrent.atomic.AtomicInteger;

public class Hits {
    private int hits;
    private final AtomicInteger refCnt = new AtomicInteger(1);

    public void hit() {
        hits++;
    }

    public void retain() {
        refCnt.incrementAndGet();
    }

    public synchronized void bump(Counter c) {
        c.refCount++;
    }
}
