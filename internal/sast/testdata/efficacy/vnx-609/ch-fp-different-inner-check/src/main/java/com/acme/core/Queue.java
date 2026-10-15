package com.acme.core;

public class Queue {
    private Worker worker;
    private boolean stopped;

    void start() {
        if (worker == null) {
            synchronized (this) {
                if (!stopped) {
                    worker = new Worker();
                }
            }
        }
    }
}
