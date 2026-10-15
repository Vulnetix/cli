package com.acme;

import java.util.concurrent.locks.ReentrantLock;

public class Ledger {
    private final ReentrantLock lock = new ReentrantLock();

    public void post(Entry e) {
        lock.lock();
        try {
            entries.add(e);
        } finally {
            pending--;
            metrics.record("post");
            log.debug("posted {}", e);
            notifyListeners(e);
            lock.unlock();
        }
    }
}
