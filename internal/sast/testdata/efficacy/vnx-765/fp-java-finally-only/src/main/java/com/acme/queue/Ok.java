package com.acme.queue;

import java.util.concurrent.locks.ReentrantLock;

public class Ok {
    private final ReentrantLock lock = new ReentrantLock();
    private final ReentrantLock other = new ReentrantLock();

    public Item poll() {
        lock.lock();
        try {
            return items.remove(0);
        } finally {
            lock.unlock();
        }
    }

    public void handOff() {
        lock.lock();
        try {
            lock.unlock();
            slowCall();
            lock.lock();
        } finally {
            lock.unlock();
        }
    }

    public void twoLocks() {
        lock.lock();
        other.lock();
        other.unlock();
        lock.unlock();
    }

    public void sequential() {
        lock.lock();
        work();
        lock.unlock();
        lock.lock();
        work();
        lock.unlock();
    }

    public void early(boolean bad) {
        lock.lock();
        if (bad) {
            lock.unlock();
            return;
        }
        work();
        lock.unlock();
    }
}
