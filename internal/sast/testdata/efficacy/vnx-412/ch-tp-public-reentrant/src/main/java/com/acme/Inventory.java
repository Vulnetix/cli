package com.acme;

import java.util.concurrent.locks.ReentrantLock;

public class Inventory {
~>    public final ReentrantLock lock = new ReentrantLock();
    private int stock;

    public void take() {
        lock.lock();
        try {
            stock--;
        } finally {
            lock.unlock();
        }
    }
}
