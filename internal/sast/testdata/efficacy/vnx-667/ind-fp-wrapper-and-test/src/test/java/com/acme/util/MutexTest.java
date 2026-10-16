package com.acme.util;

import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.concurrent.locks.ReentrantLock;
import org.junit.jupiter.api.Test;

class MutexTest {
    @Test
    void holdsLock() {
        ReentrantLock lock = new ReentrantLock();
        lock.lock();
        assertTrue(lock.isHeldByCurrentThread());
        lock.unlock();
    }
}
