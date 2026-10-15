package com.acme.cache;

import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

public class Guards {
    private final ReentrantLock shared = new ReentrantLock();
    private final Coordinator coordinator = new Coordinator();

    public void enter() {
        coordinator.acquire(shared);
    }

    public void leave() {
        shared.unlock();
    }

    static void release(Lock l) {
        l.unlock();
    }

    static class Coordinator {
        void acquire(Lock l) {}
    }
}
