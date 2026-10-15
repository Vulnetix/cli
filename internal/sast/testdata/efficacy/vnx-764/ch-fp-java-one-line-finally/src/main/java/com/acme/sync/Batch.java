package com.acme.sync;

import java.util.concurrent.locks.ReentrantLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;

public class Batch {
    private final ReentrantLock lock = new ReentrantLock();
    private final ReentrantReadWriteLock rw = new ReentrantReadWriteLock();
    private int a;
    private int b;

    public void run() {
        lock.lock();
        try { a++; } finally { lock.unlock(); }
        lock.lock();
        try { b++; } finally { lock.unlock(); }
    }

    public int downgrade() {
        rw.writeLock().lock();
        try {
            a = 0;
            rw.readLock().lock();
        } finally {
            rw.writeLock().unlock();
        }
        try {
            return a;
        } finally {
            rw.readLock().unlock();
        }
    }

    public boolean attempt() {
        lock.lock();
        try {
            return lock.tryLock();
        } finally {
            lock.unlock();
        }
    }
}
