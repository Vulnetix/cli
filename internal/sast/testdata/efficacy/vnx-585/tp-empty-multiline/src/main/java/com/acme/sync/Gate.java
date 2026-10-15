package com.acme.sync;

public class Gate {
    private final Object mutex = new Object();

    void pass() {
~>        synchronized (mutex) {
        }
~>        synchronized (Gate.class)
        {
            // wait for writers to finish
        }
    }
}
