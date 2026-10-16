package com.acme;

public class Counter {
~>    private Object lock;
    private int n;

    public void inc() {
        synchronized (lock) {
            n++;
        }
    }
}
