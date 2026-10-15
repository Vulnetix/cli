package com.acme.sync;

public class Job {
    private static final long LOCK_TIMEOUT_MS = 30_000L;
    private PowerManager.WakeLock wl;

    void run() {
        wl.acquire(LOCK_TIMEOUT_MS);
        wl.acquire(/* bounded */ 5000);
        pool.acquire();
    }
}
