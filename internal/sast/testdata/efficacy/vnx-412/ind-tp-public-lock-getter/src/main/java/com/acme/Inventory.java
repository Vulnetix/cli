package com.acme;

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;

public class Inventory {
    private final ReadWriteLock rw = new ReentrantReadWriteLock();
    private final Map<String, Integer> stock = new HashMap<>();

~>    public ReadWriteLock getLock() {
        return rw;
    }

    public int quantity(String sku) {
        rw.readLock().lock();
        try {
            return stock.getOrDefault(sku, 0);
        } finally {
            rw.readLock().unlock();
        }
    }
}
