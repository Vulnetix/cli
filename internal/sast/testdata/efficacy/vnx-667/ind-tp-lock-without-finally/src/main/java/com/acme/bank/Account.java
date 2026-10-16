package com.acme.bank;

import java.util.concurrent.locks.ReentrantLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;

public class Account {
    private final ReentrantLock lock = new ReentrantLock();
    private final ReentrantReadWriteLock rw = new ReentrantReadWriteLock();
    private long balance;

    public void withdraw(long amount) {
~>        lock.lock();
        if (amount > balance) {
            throw new IllegalStateException("insufficient funds");
        }
        balance -= amount;
        lock.unlock();
    }

    public long snapshot() {
~>        rw.readLock().lock();
        long b = audit(balance);
        rw.readLock().unlock();
        return b;
    }

    private long audit(long v) {
        if (v < 0) throw new IllegalStateException("negative");
        return v;
    }
}
