package com.acme.queue;

import java.util.concurrent.locks.ReentrantLock;

public class Queue {
    private final ReentrantLock lock = new ReentrantLock();

    public Item poll() {
        lock.lock();
        try {
            if (items.isEmpty()) {
                lock.unlock();
                return null;
            }
            return items.remove(0);
        } finally {
~>            lock.unlock();
        }
    }

    public void drain() {
        lock.lock();
        try {
            items.clear();
            lock.unlock();
        } catch (RuntimeException e) {
            log(e);
        } finally {
~>            lock.unlock();
        }
    }
}
