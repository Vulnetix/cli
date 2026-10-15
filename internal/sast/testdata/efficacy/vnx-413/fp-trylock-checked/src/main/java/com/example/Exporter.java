package com.example;

import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.ReentrantLock;

public class Exporter {
    private final ReentrantLock lock = new ReentrantLock();

    public boolean export() throws InterruptedException {
        if (!lock.tryLock(2, TimeUnit.SECONDS)) {
            return false;
        }
        try {
            write();
        } finally {
            lock.unlock();
        }
        boolean got = lock.tryLock();
        return got;
    }
}
