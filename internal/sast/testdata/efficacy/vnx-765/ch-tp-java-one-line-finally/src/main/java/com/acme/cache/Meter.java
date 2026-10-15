package com.acme.cache;

import java.util.concurrent.locks.ReentrantLock;

public class Meter {
    private final ReentrantLock lock = new ReentrantLock();
    private long count;

    public long tick() {
        lock.lock();
        try {
            count++;
            lock.unlock();
            return count;
~>        } finally { lock.unlock(); }
    }
}
