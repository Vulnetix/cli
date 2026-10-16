package com.acme;

import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

public class Ledger {
    private final Lock lock = new ReentrantLock();
    private long total;

    public void add(long v) {
        lock.lock();
        try {
            total += v;
        } finally {
            lock.unlock();
        }
    }

    public void addInterruptibly(long v) throws InterruptedException {
        lock.lockInterruptibly();
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
}
