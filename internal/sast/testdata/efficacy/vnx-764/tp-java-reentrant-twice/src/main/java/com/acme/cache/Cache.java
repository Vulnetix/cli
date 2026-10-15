package com.acme.cache;

import java.util.concurrent.locks.ReentrantLock;

public class Cache {
    private final ReentrantLock lock = new ReentrantLock();

    public void put(String k, String v) {
        lock.lock();
        try {
            if (k.isEmpty()) {
~>                lock.lock();
                k = "default";
            }
            store(k, v);
        } finally {
            lock.unlock();
        }
    }

    public void evict() throws InterruptedException {
        this.lock.lockInterruptibly();
~>        this.lock.lock();
        try {
            clear();
        } finally {
            this.lock.unlock();
        }
    }
}
