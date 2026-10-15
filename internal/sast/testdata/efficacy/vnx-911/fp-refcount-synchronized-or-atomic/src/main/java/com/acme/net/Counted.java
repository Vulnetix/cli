package com.acme.net;

import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.locks.ReentrantLock;

public class Counted {
    private int refCount = 1;
    private int useCount;
    private long refCnt;
    private final AtomicInteger references = new AtomicInteger(1);
    private final ReentrantLock lock = new ReentrantLock();

    public synchronized void retain() {
        refCount++;
    }

    public void release() {
        synchronized (this) {
            refCount--;
        }
        references.decrementAndGet();
    }

    public void touch() {
        lock.lock();
        try {
            useCount++;
        } finally {
            lock.unlock();
        }
    }

    public Counted(long initial) {
        refCnt = initial;
    }
}
