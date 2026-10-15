package com.example;

import java.util.concurrent.locks.ReadWriteLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;

public class SessionStore {
    private final ReadWriteLock rw = new ReentrantReadWriteLock();
    private final Object monitor = new Object();

~>    public ReadWriteLock getLock() {
        return rw;
    }

~>    public Object getMonitor() { return monitor; }
}
