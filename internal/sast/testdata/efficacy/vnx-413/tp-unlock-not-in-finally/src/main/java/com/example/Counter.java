package com.example;

import java.util.concurrent.locks.ReentrantLock;

public class Counter {
    private final ReentrantLock lock = new ReentrantLock();
    private int value;

    public void increment(int by) {
~>        lock.lock();
        value = Math.addExact(value, by);
        lock.unlock();
    }

    public void incrementInterruptibly() throws InterruptedException {
~>        this.lock.lockInterruptibly();
        value++;
        this.lock.unlock();
    }
}
