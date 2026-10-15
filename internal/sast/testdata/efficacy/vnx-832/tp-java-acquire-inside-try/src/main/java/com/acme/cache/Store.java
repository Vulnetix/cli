package com.acme.cache;

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.concurrent.locks.ReentrantLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;

public class Store {
    private final ReentrantLock lock = new ReentrantLock();
    private final ReadWriteLock rw = new ReentrantReadWriteLock();
    private final Map<String, String> data = new HashMap<>();

    public void put(String k, String v) throws InterruptedException {
        try {
            lock.lockInterruptibly();
            data.put(k, v);
        } finally {
~>            lock.unlock();
        }
    }

    public String get(String k) throws InterruptedException {
        try {
            if (!rw.readLock().tryLock(1, TimeUnit.SECONDS)) {
                return null;
            }
            return data.get(k);
        } finally {
~>            rw.readLock().unlock();
        }
    }

    public void remove(String k) {
        try {
            if (this.lock.tryLock()) {
                data.remove(k);
            }
        }
~>        finally { this.lock.unlock(); }
    }
}
