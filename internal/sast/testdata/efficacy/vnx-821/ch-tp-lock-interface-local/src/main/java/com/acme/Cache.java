package com.acme;

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;

public class Cache {
    private final ReadWriteLock rw = new ReentrantReadWriteLock();
    private final Map<String, String> data = new HashMap<>();

    public void put(String k, String v) {
        Lock writeLock = rw.writeLock();
~>        synchronized (writeLock) {
            data.put(k, v);
        }
    }
}
