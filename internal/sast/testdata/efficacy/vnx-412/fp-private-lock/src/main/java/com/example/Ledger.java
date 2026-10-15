package com.example;

import java.util.concurrent.locks.ReentrantLock;

public class Ledger {
    private final Object lock = new Object();
    private static final ReentrantLock WRITE_LOCK = new ReentrantLock();
    private long balance;

    public void credit(long amount) {
        synchronized (lock) {
            balance += amount;
        }
    }

    private ReentrantLock getLock() {
        return WRITE_LOCK;
    }
}
