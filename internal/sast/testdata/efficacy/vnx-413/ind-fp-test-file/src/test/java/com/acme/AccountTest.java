package com.acme;

import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.concurrent.locks.ReentrantLock;
import org.junit.jupiter.api.Test;

class AccountTest {

    @Test
    void lockIsHeldByOtherThread() throws Exception {
        ReentrantLock lock = new ReentrantLock();
        lock.lock();
        Thread t = new Thread(() -> assertTrue(lock.isLocked()));
        t.start();
        t.join();
        lock.unlock();
    }
}
