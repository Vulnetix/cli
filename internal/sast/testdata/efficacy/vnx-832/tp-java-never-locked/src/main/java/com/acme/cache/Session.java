package com.acme.cache;

import java.util.concurrent.locks.ReentrantLock;

public class Session {
    private final ReentrantLock stateLock = new ReentrantLock();
    private final ReentrantLock ioLock = new ReentrantLock();
    private boolean open;

    public void close() {
        synchronized (this) {
            open = false;
        }
~>        stateLock.unlock();
    }

    public void send(byte[] b) {
        ioLock.lock();
        try {
            write(b);
        } finally {
            ioLock.unlock();
        }
    }

    private void write(byte[] b) {}
}
