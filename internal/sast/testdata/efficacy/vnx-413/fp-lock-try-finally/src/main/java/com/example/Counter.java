package com.example;

import java.util.concurrent.locks.ReentrantLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;

public class Counter {
    private final ReentrantLock lock = new ReentrantLock();
    private final ReentrantReadWriteLock rw = new ReentrantReadWriteLock();
    private int value;

    public void increment(int by) {
        lock.lock();
        // the body may throw
        try {
            value = Math.addExact(value, by);
        } finally {
            lock.unlock();
        }
    }

    public int read() {
        rw.readLock().lock();
        try {
            return value;
        } finally {
            rw.readLock().unlock();
        }
    }
}
