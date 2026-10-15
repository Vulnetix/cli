package com.acme.stock;

import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantReadWriteLock;

public class Warehouse {
    private final Lock stockLock = new ReentrantReadWriteLock().writeLock();
    private final Lock priceLock = new ReentrantReadWriteLock().writeLock();

    public void restock(int n) {
        stockLock.lock();
        try {
            add(n);
        } finally {
            stockLock.unlock();
        }
        priceLock.lock();
        try {
            reprice();
        } finally {
            priceLock.unlock();
        }
    }

    public void sale() {
        priceLock.lock();
        try {
            discount();
        } finally {
            priceLock.unlock();
        }
        stockLock.lock();
        try {
            add(-1);
        } finally {
            stockLock.unlock();
        }
    }

    private void add(int n) {}
    private void reprice() {}
    private void discount() {}
}
