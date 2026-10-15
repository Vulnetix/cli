package com.acme;

public class Cache {
    private Object mutex = new Object();
    private int entries;

    public void put() {
~>        synchronized (mutex) {
            entries++;
        }
    }

    public void reset() {
        mutex = new Object();
        entries = 0;
    }
}
