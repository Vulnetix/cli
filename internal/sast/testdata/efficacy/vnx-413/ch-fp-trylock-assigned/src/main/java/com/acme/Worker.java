package com.acme;

import java.util.concurrent.locks.ReentrantLock;

public class Worker {
    private final ReentrantLock lock = new ReentrantLock();

    public void tick() {
        final boolean acquired = lock.tryLock();
        if (!acquired) {
            return;
        }
        try {
            work();
        } finally {
            lock.unlock();
        }
    }
}
