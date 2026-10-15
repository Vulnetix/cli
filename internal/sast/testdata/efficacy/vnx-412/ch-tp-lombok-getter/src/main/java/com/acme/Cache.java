package com.acme;

import java.util.concurrent.locks.ReentrantLock;
import lombok.Getter;

public class Cache {
~>    @Getter private final ReentrantLock lock = new ReentrantLock();

    public void put(String k, String v) {
        lock.lock();
        try {
            store(k, v);
        } finally {
            lock.unlock();
        }
    }
}
