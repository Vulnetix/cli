package com.acme.sync;

import java.util.concurrent.locks.ReentrantLock;

public class Ledger {
    private final ReentrantLock lock = new ReentrantLock();
    private long balance;

    public void transfer(long amount) throws InterruptedException {
        lock.lockInterruptibly();
        try {
            if (amount > 0) {
~>                lock.lockInterruptibly();
                balance += amount;
            }
        } finally {
            lock.unlock();
        }
    }
}
