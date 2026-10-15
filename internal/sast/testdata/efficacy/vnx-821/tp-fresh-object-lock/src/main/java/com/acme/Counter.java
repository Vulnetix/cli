package com.acme;

public class Counter {
    private int value;

    public void increment() {
~>        synchronized (new Object()) {
            value++;
        }
    }
}
