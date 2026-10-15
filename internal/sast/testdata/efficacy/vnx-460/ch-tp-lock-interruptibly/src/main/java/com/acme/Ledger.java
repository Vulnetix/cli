package com.acme;

import java.util.concurrent.locks.ReentrantLock;

public class Ledger {
    private final ReentrantLock guard = new ReentrantLock();
    private long balance;

    public void credit(long amount) throws InterruptedException {
~>        guard.lockInterruptibly();
        validate(amount);
        balance += amount;
        guard.unlock();
    }
}
