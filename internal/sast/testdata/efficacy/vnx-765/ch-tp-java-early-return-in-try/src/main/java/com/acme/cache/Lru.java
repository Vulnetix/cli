package com.acme.cache;

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.locks.ReentrantReadWriteLock;

public class Lru {
    private final ReentrantReadWriteLock rw = new ReentrantReadWriteLock();
    private final Map<String, String> map = new HashMap<>();

    public String get(String k) {
        rw.readLock().lock();
        try {
            String v = map.get(k);
            if (v == null) {
                rw.readLock().unlock();
                return null;
            }
            return v;
        } finally {
~>            rw.readLock().unlock();
        }
    }
}
