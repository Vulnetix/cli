package com.example;

public class Notes {
    // lock.lock(); without try/finally leaks the lock on an exception
    /* synchronized (new Object()) protects nothing */
    static final String HINT = "lock.tryLock(); ignores the result";
}
