package com.acme;

public class Doc {
    // synchronized ("registry") { ... }
    // lock.lock();
    /*
     * Never write synchronized (LOCK) on a String constant.
     */
    private static final String HELP = "synchronized (\"x\") and lock.lock();";
}
