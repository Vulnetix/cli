package com.example;

import java.util.concurrent.locks.ReentrantLock;

public class Ledger {
~>    public final Object lock = new Object();
~>    public static final ReentrantLock WRITE_LOCK = new ReentrantLock();
    private long balance;

    public void credit(long amount) {
        synchronized (lock) {
            balance += amount;
        }
    }
}
