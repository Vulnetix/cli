package com.acme;

import java.util.concurrent.locks.ReentrantLock;

public class Good {
    private final ReentrantLock lock = new ReentrantLock();
    private final ReentrantLock other = new ReentrantLock();

    public void a(boolean f) {
        lock.lock();
        try {
            work();
        } finally {
            lock.unlock();
        }
    }

    public void b(boolean f) {
        lock.lock();
        if (f) {
            lock.unlock();
        } else {
            work();
            lock.unlock();
        }
    }

    public void c() {
        lock.lock();
        other.lock();
        other.unlock();
        lock.unlock();
    }

    private void work() {}
}
