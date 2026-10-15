package com.example;

import java.util.concurrent.locks.ReentrantLock;

public class Counter {
    private final ReentrantLock lock = new ReentrantLock();
    private long value;

    public void add(long delta) {
~>        lock.lock();
        validate(delta);
        value += delta;
        lock.unlock();
    }

    private void validate(long d) {
        if (d < 0) throw new IllegalArgumentException("negative");
    }
}
