package com.acme;

import java.util.Map;
import java.util.concurrent.locks.ReentrantReadWriteLock;

public class Registry {
    private final ReentrantReadWriteLock rw = new ReentrantReadWriteLock();
    private Map<String, String> map;

    public String get(String k) {
        rw.readLock().lock();
        try {
            String v = map.get(k);
            if (v == null) {
~>                rw.writeLock().lock();
                map.put(k, "d");
            }
            return v;
        } finally {
            rw.readLock().unlock();
        }
    }
}
