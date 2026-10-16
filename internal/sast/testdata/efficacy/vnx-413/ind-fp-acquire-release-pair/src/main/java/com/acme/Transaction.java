package com.acme;

import java.util.concurrent.locks.ReentrantLock;

public class Transaction implements AutoCloseable {
    private static final ReentrantLock GLOBAL = new ReentrantLock();

    public static Transaction begin() {
        GLOBAL.lock();
        return new Transaction();
    }

    @Override
    public void close() {
        GLOBAL.unlock();
    }
}
