package com.acme;

import java.util.concurrent.locks.ReentrantLock;

public class Ledger {
    private final ReentrantLock mutex = new ReentrantLock();

    public void post(long cents) {
~>        this.mutex.lock();
        try {
            write(cents);
            this.mutex.unlock();
        } catch (RuntimeException e) {
            this.mutex.unlock();
            throw e;
        }
    }
}
