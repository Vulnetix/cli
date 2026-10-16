package com.acme;

import java.util.concurrent.locks.ReentrantLock;

public class LedgerWriter {
~>    public static final ReentrantLock WRITE_LOCK = new ReentrantLock();

    public void append(Ledger ledger, Entry e) {
        WRITE_LOCK.lock();
        try {
            ledger.append(e);
        } finally {
            WRITE_LOCK.unlock();
        }
    }
}
