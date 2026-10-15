package com.acme;

import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

public class Queue {
    private final Lock lock = new ReentrantLock();
    private int size;

    public void add() throws InterruptedException {
~>        lock.lockInterruptibly();
        size++;
        notifyWaiters();
        lock.unlock();
    }
}
