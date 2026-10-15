package com.acme.sync;

import java.util.ArrayDeque;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.ReentrantLock;

public class Queue {
    private final ReentrantLock lock = new ReentrantLock();
    private final ArrayDeque<String> items = new ArrayDeque<>();

    public void push(String s) throws InterruptedException {
        lock.lockInterruptibly();
        try {
            items.push(s);
        } finally {
            lock.unlock();
        }
    }

    public boolean offer(String s) throws InterruptedException {
        if (!lock.tryLock(1, TimeUnit.SECONDS)) {
            return false;
        }
        try {
            return items.offer(s);
        } finally {
            lock.unlock();
        }
    }
}
