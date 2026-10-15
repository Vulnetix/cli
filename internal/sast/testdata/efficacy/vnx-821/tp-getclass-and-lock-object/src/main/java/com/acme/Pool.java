package com.acme;

import java.util.concurrent.locks.ReentrantLock;

public class Pool {
    private final ReentrantLock lock = new ReentrantLock();
    private int free;

    public void release() {
~>        synchronized (getClass()) {
            free++;
        }
    }

    public void take() {
~>        synchronized (lock) {
            free--;
        }
    }
}
