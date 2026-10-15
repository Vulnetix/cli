package com.acme;

public class LockSettings {
    public static final long LOCK_TIMEOUT_MS = 5000L;
    public static final String LOCK_PREFIX = "lock:";
    public static final int MAX_LOCKS = 64;

    public String key(String id) {
        return LOCK_PREFIX + id;
    }
}
