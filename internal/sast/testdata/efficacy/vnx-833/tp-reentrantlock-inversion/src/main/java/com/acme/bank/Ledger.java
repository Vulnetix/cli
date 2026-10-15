package com.acme.bank;

import java.util.concurrent.locks.ReentrantLock;

public class Ledger {
    private final ReentrantLock readLock = new ReentrantLock();
    private final ReentrantLock writeLock = new ReentrantLock();

    void post(Entry e) {
        readLock.lock();
        try {
~>            writeLock.lock();
            try {
                entries.add(e);
            } finally {
                writeLock.unlock();
            }
        } finally {
            readLock.unlock();
        }
    }

    void compact() {
        writeLock.lock();
        try {
~>            readLock.lock();
            try {
                entries.compact();
            } finally {
                readLock.unlock();
            }
        } finally {
            writeLock.unlock();
        }
    }
}
