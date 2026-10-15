package com.acme;

import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

public class Gate {
    private final Lock lock = new ReentrantLock();

    public boolean enter() throws InterruptedException {
        if (lock.tryLock(
                5, TimeUnit.SECONDS)) {
            try {
                return true;
            } finally {
                lock.unlock();
            }
        }
        final boolean acquired = lock.tryLock();
        if (!acquired) {
            return false;
        }
        lock.unlock();
        return lock.tryLock();
    }
}
