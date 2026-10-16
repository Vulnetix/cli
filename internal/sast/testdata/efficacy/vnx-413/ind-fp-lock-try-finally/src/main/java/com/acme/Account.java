package com.acme;

import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;
import java.util.concurrent.locks.StampedLock;

public class Account {
    private final Lock lock = new ReentrantLock();
    private final StampedLock sl = new StampedLock();
    private long balance;

    public void deposit(long by) {
        lock.lock();
        try {
            balance = Math.addExact(balance, by);
        } finally {
            lock.unlock();
        }
    }

    public void withdraw(long by) throws InterruptedException {
        lock.lockInterruptibly();
        try {
            if (balance < by) {
                throw new IllegalStateException("insufficient");
            }
            balance -= by;
        } finally {
            lock.unlock();
        }
    }
}
