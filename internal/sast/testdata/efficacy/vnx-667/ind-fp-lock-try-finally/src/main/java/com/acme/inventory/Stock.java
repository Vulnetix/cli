package com.acme.inventory;

import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

public class Stock {
    private final Lock lock = new ReentrantLock();
    private int units;

    public void reserve(int n) {
        lock.lock();
        try {
            if (n > units) {
                throw new IllegalArgumentException("not enough stock");
            }
            units -= n;
        } finally {
            lock.unlock();
        }
    }

    public void release(int n) throws InterruptedException {
        try {
            lock.lockInterruptibly();
            units += n;
        } finally {
            lock.unlock();
        }
    }

    public boolean tryReserve(int n) throws InterruptedException {
        if (lock.tryLock(100, TimeUnit.MILLISECONDS)) {
            try {
                units -= n;
                return true;
            } finally {
                lock.unlock();
            }
        }
        return false;
    }
}
