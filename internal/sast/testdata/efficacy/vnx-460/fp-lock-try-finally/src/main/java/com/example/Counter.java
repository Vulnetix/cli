package com.example;

import java.util.concurrent.locks.ReentrantLock;

public class Counter {
    private final ReentrantLock lock = new ReentrantLock();
    private long value;

    public void add(long delta) {
        lock.lock();
        try {
            value += delta;
        } finally {
            lock.unlock();
        }
    }
}
