package com.acme.cache;

import java.util.concurrent.locks.ReentrantLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;

public class Ok {
    private final ReentrantLock lock = new ReentrantLock();
    private final ReentrantLock other = new ReentrantLock();
    private final ReentrantReadWriteLock rw = new ReentrantReadWriteLock();

    public void a() {
        lock.lock();
        try {
            work();
        } finally {
            lock.unlock();
        }
        lock.lock();
        try {
            work();
        } finally {
            lock.unlock();
        }
    }

    public void b(boolean fast) {
        if (fast) {
            lock.lock();
        } else {
            lock.lock();
        }
        other.lock();
        other.unlock();
        lock.unlock();
    }

    public void downgrade() {
        rw.writeLock().lock();
        rw.readLock().lock();
        rw.writeLock().unlock();
        rw.readLock().unlock();
    }

    public void spawn() {
        lock.lock();
        new Thread(() -> {
            lock.lock();
            lock.unlock();
        }).start();
        lock.unlock();
    }

    public boolean tryIt() {
        lock.lock();
        // lock.lock() again would leak a hold count
        boolean ok = lock.tryLock();
        lock.unlock();
        return ok;
    }
}
