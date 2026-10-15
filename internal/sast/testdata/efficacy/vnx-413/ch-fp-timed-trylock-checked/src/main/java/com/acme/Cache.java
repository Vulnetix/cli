package com.acme;

import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.ReentrantLock;

public class Cache {
    private final ReentrantLock lock = new ReentrantLock();

    public void refresh() throws InterruptedException {
        if (!lock.tryLock(2, TimeUnit.SECONDS)) {
            throw new IllegalStateException("busy");
        }
        try {
            reload();
        } finally {
            lock.unlock();
        }
    }
}
