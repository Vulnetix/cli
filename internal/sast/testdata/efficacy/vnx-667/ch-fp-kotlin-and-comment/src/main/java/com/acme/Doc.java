package com.acme;

/**
 * Never write synchronized ("LOCK") { ... }: interned strings are shared.
 * lock.lock();
 */
public class Doc {
    private static final String MSG = "use synchronized (\"x\") never";
}
