package com.acme.bank;

public class Sequential {
    private final Object left = new Object();
    private final Object right = new Object();

    void forward() {
        synchronized (left) {
            stepOne();
        }
        synchronized (right) {
            stepTwo();
        }
    }

    void backward() {
        synchronized (right) {
            stepTwo();
        }
        synchronized (left) {
            stepOne();
        }
    }

    void locks() {
        right.lock();
        right.unlock();
        left.lock();
        left.unlock();
    }

    void locksReverse() {
        left.lock();
        left.unlock();
        right.lock();
        right.unlock();
    }
}
