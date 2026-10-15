package com.acme.cache;

import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.ReentrantLock;

public class Refresher {
    private final ReentrantLock lock = new ReentrantLock();
    private final ReentrantLock flushLock = new ReentrantLock();

    public void refresh() {
        lock.tryLock();
        try {
            reload();
        } finally {
~>            lock.unlock();
        }
    }

    public void flush() throws InterruptedException {
        flushLock.tryLock(250, TimeUnit.MILLISECONDS);
        write();
~>        flushLock.unlock();
    }

    private void reload() {}

    private void write() {}
}
