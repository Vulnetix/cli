package com.acme;

import java.util.concurrent.locks.ReentrantReadWriteLock;

public class Cache {
    private final ReentrantReadWriteLock rw = new ReentrantReadWriteLock();

    public Object get(String key) {
~>        rw.readLock().lock();
        Object v = map.get(key);
        rw.readLock().unlock();
        return v;
    }
}
