package com.acme;

import java.util.concurrent.locks.ReentrantLock;

public class Counter {
    private final ReentrantLock lock = new ReentrantLock();
    private int n;

    public void inc() {
        lock.lock();
        try {
            n++;
~>            lock.lock();
            n++;
        } finally {
            lock.unlock();
        }
    }
}
