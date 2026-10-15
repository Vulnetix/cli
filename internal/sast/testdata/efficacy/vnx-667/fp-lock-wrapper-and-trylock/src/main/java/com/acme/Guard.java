package com.acme;

public class Guard {
    public void lock() {
        inner.lock();
    }

    public void unlock() {
        inner.unlock();
    }

    public boolean attempt() {
        if (inner.tryLock()) {
            try {
                return true;
            } finally {
                inner.unlock();
            }
        }
        return false;
    }

    public void file() throws Exception {
        FileLock fl = channel.lock();
        fl.release();
    }
}
