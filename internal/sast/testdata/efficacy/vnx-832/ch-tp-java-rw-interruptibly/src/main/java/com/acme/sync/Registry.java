package com.acme.sync;

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;

public class Registry {
    private final ReadWriteLock rw = new ReentrantReadWriteLock();
    private final Map<String, String> entries = new HashMap<>();

    public void put(String k, String v) throws InterruptedException {
        try {
            rw.writeLock().lockInterruptibly();
            entries.put(k, v);
        } finally {
~>            rw.writeLock().unlock();
        }
    }
}
