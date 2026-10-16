package com.acme;

public class Counter {
    private static int instances;
    private long value;

    public Counter() {
        synchronized (Counter.class) {
            instances++;
        }
    }

    public synchronized void increment() {
        value++;
    }

    public long get() {
        synchronized (this) {
            return value;
        }
    }
}
