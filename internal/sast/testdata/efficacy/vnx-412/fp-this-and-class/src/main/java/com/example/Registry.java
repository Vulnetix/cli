package com.example;

public class Registry {
    private int count;

    public synchronized void add() {
        count++;
    }

    public void reset() {
        synchronized (this) {
            count = 0;
        }
        synchronized (Registry.class) {
            count = 0;
        }
    }
}
