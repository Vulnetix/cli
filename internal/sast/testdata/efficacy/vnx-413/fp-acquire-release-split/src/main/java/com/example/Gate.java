package com.example;

import java.util.concurrent.locks.ReentrantLock;

public class Gate implements AutoCloseable {
    private final ReentrantLock lock = new ReentrantLock();

    public Gate open() {
        lock.lock();
        return this;
    }

    @Override
    public void close() {
        lock.unlock();
    }
}
