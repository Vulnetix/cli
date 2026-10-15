package com.acme.cache;

public class Doc {
    // lock.tryLock(); try { ... } finally { lock.unlock(); } is wrong
    /* try { lock.lockInterruptibly(); } finally { lock.unlock(); } */
    static final String HINT = "lock.tryLock(); lock.unlock();";

    void explain(java.io.PrintStream out) {
        out.println("never call lock.unlock() without lock.lock()");
    }
}
