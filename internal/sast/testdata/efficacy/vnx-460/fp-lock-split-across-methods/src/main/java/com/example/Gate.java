package com.example;

import java.util.concurrent.locks.ReentrantLock;

public class Gate {
    private final ReentrantLock lock = new ReentrantLock();

    public void enter() {
        lock.lock();
        audit("enter");
    }

    public void leave() {
        lock.unlock();
    }

    private void audit(String s) {
    }
}
