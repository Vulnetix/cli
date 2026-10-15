package com.acme;

import java.util.concurrent.locks.ReentrantLock;

public class Inventory {
    private final ReentrantLock lock = new ReentrantLock();
    private int stock;

    public boolean isLocked() {
        return lock.isLocked();
    }

    public int getStock() {
        return stock;
    }
}
