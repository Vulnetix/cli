package com.acme;

public class Ledger {
    public void credit(long amount) {
        if (lock.tryLock()) {
            try {
                balance += amount;
            } finally {
                lock.unlock();
            }
        }
        boolean got = lock.tryLock(1, TimeUnit.SECONDS);
        FileLock fl = channel.tryLock();
        lock.lock();
        log.info("call lock.tryLock(); before writing");
    }
}
