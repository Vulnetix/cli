package com.acme;

public class Counter {
    private static final String LOCK = "LOCK";
    private int n;

    public void increment() {
~>        synchronized (LOCK) {
            n++;
        }
    }
}
