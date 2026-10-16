package com.acme;

import java.util.concurrent.locks.ReentrantReadWriteLock;

public class Pool {
    private final ReentrantReadWriteLock rw = new ReentrantReadWriteLock();
    private int size;

    public int size() {
        try {
            rw.readLock().lock();
            return size;
        } finally {
            rw.readLock().unlock();
        }
    }

    public void grow() {
        rw.writeLock().lock();
        try {
            size++;
        } finally {
            rw.writeLock().unlock();
        }
    }
}
