package com.acme.pool;

import java.util.concurrent.Semaphore;
import java.util.concurrent.locks.ReentrantLock;

public class Pool {
    private final Semaphore permits = new Semaphore(4);
    private final ReentrantLock lock = new ReentrantLock();

    void use() throws InterruptedException {
        permits.acquire();
        lock.lock();
        connection.acquire();
    }
}
