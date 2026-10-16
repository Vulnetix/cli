package com.acme.util;

import java.util.concurrent.locks.ReentrantLock;

public class Mutex {
    private final ReentrantLock inner = new ReentrantLock();

    public void lock() {
        inner.lock();
    }

    public void unlock() {
        inner.unlock();
    }
}
