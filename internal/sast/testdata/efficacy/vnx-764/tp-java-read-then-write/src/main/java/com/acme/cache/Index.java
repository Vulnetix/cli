package com.acme.cache;

import java.util.concurrent.locks.ReentrantReadWriteLock;

public class Index {
    private final ReentrantReadWriteLock rw = new ReentrantReadWriteLock();

    public String lookup(String k) {
        rw.readLock().lock();
        try {
            String v = find(k);
            if (v == null) {
~>                rw.writeLock().lock();
                v = load(k);
                rw.writeLock().unlock();
            }
            return v;
        } finally {
            rw.readLock().unlock();
        }
    }
}
