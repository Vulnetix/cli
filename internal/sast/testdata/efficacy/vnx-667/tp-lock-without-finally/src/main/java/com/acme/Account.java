package com.acme;

import java.util.concurrent.locks.ReentrantLock;

public class Account {
    private final ReentrantLock lock = new ReentrantLock();
    private long balance;

    public void withdraw(long amount) {
~>        lock.lock();
        if (amount > balance) {
            throw new IllegalStateException("insufficient funds");
        }
        balance -= amount;
        lock.unlock();
    }

    public void deposit(long amount) throws InterruptedException {
~>        this.lock.lockInterruptibly();
        balance += amount;
        audit.record(amount);
        this.lock.unlock();
    }
}
