package com.acme;

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.locks.ReentrantReadWriteLock;

public class Catalog {
    private final ReentrantReadWriteLock rw = new ReentrantReadWriteLock();
    private final Map<String, Item> items = new HashMap<>();

    public Item find(String key) {
~>        rw.readLock().lock();
        return items.get(key);
    }

    public void put(String key, Item item) {
        rw.writeLock().lock();
        try {
            items.put(key, item);
        } finally {
            rw.writeLock().unlock();
        }
    }
}
