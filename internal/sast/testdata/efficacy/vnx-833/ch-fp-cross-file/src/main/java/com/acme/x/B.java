package com.acme.x;

public class B {
    void again() {
        synchronized (A.FIRST) {
            synchronized (A.SECOND) {
                hop();
            }
        }
    }

    void hop() {}
}
