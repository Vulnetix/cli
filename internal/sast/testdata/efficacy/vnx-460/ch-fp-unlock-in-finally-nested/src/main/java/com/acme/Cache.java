package com.acme;

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;

public class Cache {
    private final ReadWriteLock rw = new ReentrantReadWriteLock();
    private final Map<String, String> map = new HashMap<>();

    public String get(String key) {
        rw.readLock().lock();
        try {
            return map.get(key);
        }
        finally
        {
            rw.readLock().unlock();
        }
    }
}
