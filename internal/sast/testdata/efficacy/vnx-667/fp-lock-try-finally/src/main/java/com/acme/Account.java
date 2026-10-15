package com.acme;

import java.util.concurrent.locks.ReentrantLock;

public class Account {
    private final ReentrantLock lock = new ReentrantLock();

    public void withdraw(long amount) {
        lock.lock();
        try {
            if (amount > balance) {
                throw new IllegalStateException("insufficient funds");
            }
            balance -= amount;
        } finally {
            lock.unlock();
        }
    }

    public Object get(String key) {
        rw.readLock().lock();
        try {
            return map.get(key);
        } finally {
            rw.readLock().unlock();
        }
    }
}
