package com.acme;

import java.util.concurrent.locks.ReentrantLock;

public class Pair {
    private final ReentrantLock lock = new ReentrantLock();
    private int x;

    public void set(int v) {
        lock.lock();
        x = v;
        lock.unlock();
~>        lock.unlock();
    }
}
