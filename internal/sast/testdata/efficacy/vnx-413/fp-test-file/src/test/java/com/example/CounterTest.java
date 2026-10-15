package com.example;

import java.util.concurrent.locks.ReentrantLock;

class CounterTest {
    private final ReentrantLock lock = new ReentrantLock();

    void holdsLock() {
        lock.lock();
        lock.tryLock();
    }
}
