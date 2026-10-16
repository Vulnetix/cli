package com.acme;

import java.util.concurrent.locks.ReentrantLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;

public class Ok {
    private final ReentrantLock lock = new ReentrantLock();
    private final ReentrantReadWriteLock rw = new ReentrantReadWriteLock();

    public void a() {
        lock.lock();
        try {
            if (lock.tryLock()) {
                lock.unlock();
            }
        } finally {
            lock.unlock();
        }
    }

    public void downgrade() {
        rw.writeLock().lock();
        try {
            rw.readLock().lock();
        } finally {
            rw.writeLock().unlock();
        }
        rw.readLock().unlock();
    }

    public void lambda() {
        lock.lock();
        try {
            Runnable r = () -> {
                lock.lock();
                lock.unlock();
            };
        } finally {
            lock.unlock();
        }
    }
}
