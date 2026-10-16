package com.acme;
public class Work {
    private final Object lock = new Object();
    void run() throws Exception {
        try {
            step();
~>        } finally {
        }
~>        synchronized (lock) { }
~>        for (int i = 0; i < 3; i++) {
        }
    }
    void step() {}
}
