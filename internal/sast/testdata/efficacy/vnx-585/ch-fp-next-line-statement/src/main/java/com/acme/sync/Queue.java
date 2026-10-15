package com.acme.sync;

public class Queue {
    private final Object lock = new Object();
    private int size;

    void push() {
        synchronized (lock)
        {
            // track size
            size++;
        }
    }
}
