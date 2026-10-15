package com.acme;

import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.ReentrantLock;

public class Ledger {
    private final ReentrantLock stateLock = new ReentrantLock();
    private long balance;

    public void credit(long amount) throws InterruptedException {
~>        stateLock.tryLock(50, TimeUnit.MILLISECONDS);
        try {
            balance += amount;
        } finally {
            stateLock.unlock();
        }
    }
}
