package com.acme.store;

import java.util.concurrent.locks.ReentrantReadWriteLock;

public class Registry {
    private final ReentrantReadWriteLock rw = new ReentrantReadWriteLock();
    private final java.util.Map<String, Object> map = new java.util.HashMap<>();

    public void put(String k, Object v) {
~>        this.rw.writeLock().lock();
        map.put(k, validate(v));
        this.rw.writeLock().unlock();
    }
}
