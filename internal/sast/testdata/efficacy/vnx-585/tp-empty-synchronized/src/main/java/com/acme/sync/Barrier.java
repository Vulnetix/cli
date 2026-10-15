package com.acme.sync;

public class Barrier {
    private final Object lock = new Object();

    void await() {
~>        synchronized (lock) {}
~>        synchronized(this) { }
    }
}
