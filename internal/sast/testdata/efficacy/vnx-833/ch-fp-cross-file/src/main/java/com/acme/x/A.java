package com.acme.x;

public class A {
    static final Object FIRST = new Object();
    static final Object SECOND = new Object();

    void forward() {
        synchronized (FIRST) {
            synchronized (SECOND) {
                step();
            }
        }
    }

    void step() {}
}
