package com.example;

import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

public class Job {
    private final Lock lock = new ReentrantLock();

    public boolean runOnce(Runnable r) {
        if (!lock.tryLock()) {
            return false;
        }
        try {
            r.run();
        } finally {
            lock.unlock();
        }
        return true;
    }
}
