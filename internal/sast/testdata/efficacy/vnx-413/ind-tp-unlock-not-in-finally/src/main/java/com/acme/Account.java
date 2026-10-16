package com.acme;

import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

public class Account {
    private final Lock lock = new ReentrantLock();
    private long balance;

    public void deposit(long by) {
~>        lock.lock();
        balance = Math.addExact(balance, by);
        AuditLog.record("deposit", by);
        lock.unlock();
    }
}
