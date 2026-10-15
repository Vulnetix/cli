package com.acme;

public class Counter {
    private static final String LOCK = "LOCK";
    private final Object other = new Object();
    private int n;

    public void inc() {
~>        synchronized (LOCK) {
            n++;
        }
    }

    public void dec() {
        synchronized (other) {
            n--;
        }
    }
}
