package com.acme.sync;

import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.Lock;

public class Exporter {
    private final Lock lock;

    public Exporter(Lock lock) { this.lock = lock; }

    public boolean export(FileChannel ch) throws Exception {
        if (!lock.tryLock(2, TimeUnit.SECONDS)) {
            return false;
        }
        try {
            FileLock fl = ch.tryLock();
            if (fl == null) {
                return false;
            }
            fl.release();
            return true;
        } finally {
            lock.unlock();
        }
    }
}
