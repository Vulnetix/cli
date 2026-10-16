package com.acme;
public class Pool {
    private final Semaphore sem = new Semaphore(4);
    void use() throws InterruptedException {
        sem.acquire();
        try { work(); } finally { sem.release(); }
        lock.acquire();
        // pm.newWakeLock(0, "x").acquire();
        String s = "wakeLock.acquire()";
    }
}
