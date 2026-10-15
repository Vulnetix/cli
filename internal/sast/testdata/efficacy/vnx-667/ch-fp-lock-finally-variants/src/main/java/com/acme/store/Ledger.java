package com.acme.store;

import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

public class Ledger {
    private final Lock lock = new ReentrantLock();

    public void post(long amount) {
        lock.lock();
        try {
            balance += amount;
        } finally {
            if (((ReentrantLock) lock).isHeldByCurrentThread()) {
                lock.unlock();
            }
        }
    }

    public boolean tryPost(long amount) {
        if (!lock.tryLock()) {
            return false;
        }
        try {
            balance += amount;
            return true;
        } finally {
            lock.unlock();
        }
    }
}
