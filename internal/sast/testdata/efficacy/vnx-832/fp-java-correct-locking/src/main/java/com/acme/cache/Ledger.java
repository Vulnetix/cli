package com.acme.cache;

import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.ReentrantLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;

public class Ledger {
    private final ReentrantLock lock = new ReentrantLock();
    private final ReentrantReadWriteLock rw = new ReentrantReadWriteLock();
    private long total;

    public void add(long v) {
        lock.lock();
        try {
            total += v;
        } finally {
            lock.unlock();
        }
    }

    public boolean tryAdd(long v) {
        if (lock.tryLock()) {
            try {
                total += v;
                return true;
            } finally {
                lock.unlock();
            }
        }
        return false;
    }

    public void addInterruptibly(long v) throws InterruptedException {
        lock.lockInterruptibly();
        try {
            total += v;
        } finally {
            lock.unlock();
        }
    }

    public void addWithin(long v) throws InterruptedException {
        boolean acquired = lock.tryLock(1, TimeUnit.SECONDS);
        try {
            total += v;
        } finally {
            if (acquired) {
                lock.unlock();
            }
        }
    }

    public void timed(long v) throws InterruptedException {
        try {
            if (!lock.tryLock(1, TimeUnit.SECONDS)) {
                return;
            }
            total += v;
        } finally {
            if (lock.isHeldByCurrentThread()) lock.unlock();
        }
    }

    public long read() {
        rw.readLock().lock();
        try {
            return total;
        } finally {
            rw.readLock().unlock();
        }
    }

    public void begin() {
        lock.lock();
    }

    public void end() {
        lock.unlock();
    }
}
