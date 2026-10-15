package com.acme.stock;

import java.util.concurrent.locks.ReentrantLock;

public class Warehouse {
    private final ReentrantLock inventoryLock = new ReentrantLock();
    private final ReentrantLock ledgerLock = new ReentrantLock();

    public void ship(String sku) {
        inventoryLock.lock();
        try {
~>            ledgerLock.lock();
            try {
                record(sku);
            } finally {
                ledgerLock.unlock();
            }
        } finally {
            inventoryLock.unlock();
        }
    }

    public void reconcile() {
        ledgerLock.lock();
        try {
~>            inventoryLock.lock();
            try {
                recount();
            } finally {
                inventoryLock.unlock();
            }
        } finally {
            ledgerLock.unlock();
        }
    }

    private void record(String sku) {}
    private void recount() {}
}
