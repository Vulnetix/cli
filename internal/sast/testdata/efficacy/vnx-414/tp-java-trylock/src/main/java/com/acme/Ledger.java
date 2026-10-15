package com.acme;

import java.nio.channels.FileChannel;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.ReentrantLock;

public class Ledger {
    private final ReentrantLock lock = new ReentrantLock();
    private long balance;

    public void credit(long amount) {
~>      lock.tryLock();
        try {
            balance += amount;
        } finally {
            lock.unlock();
        }
    }

    public void debit(long amount) throws InterruptedException {
~>      this.lock.tryLock(50, TimeUnit.MILLISECONDS);
        balance -= amount;
    }

    public void persist(FileChannel channel) throws Exception {
~>      channel.tryLock();
        channel.write(serialize());
    }
}
