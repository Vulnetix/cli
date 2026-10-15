package com.example;

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;

public class Catalog {
    private final ReadWriteLock rw = new ReentrantReadWriteLock();
    private final Map<String, String> items = new HashMap<>();

    public String get(String key) {
~>        rw.readLock().lock();
        return items.get(key);
    }
}
