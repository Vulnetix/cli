package com.acme;

import java.util.concurrent.atomic.AtomicInteger;

public class SafeBuffer {
    private int refCount = 1;
    private final AtomicInteger references = new AtomicInteger(1);

    public synchronized void retain() {
        refCount++;
    }

    public boolean release() {
        return references.decrementAndGet() == 0;
    }
}
