package com.acme;

public class Queue {
    public void put(Object o) throws InterruptedException {
        try {
            lock.lockInterruptibly();
            items.add(o);
            notEmpty.signal();
        } finally {
            lock.unlock();
        }
    }
}
