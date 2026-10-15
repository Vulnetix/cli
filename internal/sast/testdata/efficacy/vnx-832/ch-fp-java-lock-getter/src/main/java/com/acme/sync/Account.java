package com.acme.sync;

import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

public class Account {
    private final Lock lock = new ReentrantLock();
    private long balance;

    public Lock getLock() {
        return lock;
    }

    /** Called by the transfer service after it took getLock().lock(). */
    public void settle(long delta) {
        balance += delta;
        lock.unlock();
    }
}
