package com.acme.bank;

import java.util.concurrent.locks.ReentrantLock;

public class Ordered {
    private final Object first = new Object();
    private final Object second = new Object();
    private final ReentrantLock outer = new ReentrantLock();
    private final ReentrantLock inner = new ReentrantLock();

    void a() {
        synchronized (first) {
            synchronized (second) {
                work();
            }
        }
    }

    void b() {
        synchronized (first) {
            synchronized (second) {
                more();
            }
        }
    }

    void c() {
        outer.lock();
        try {
            inner.lock();
            try { work(); } finally { inner.unlock(); }
        } finally {
            outer.unlock();
        }
    }

    void d() {
        outer.lock();
        try {
            inner.lock();
            try { more(); } finally { inner.unlock(); }
        } finally {
            outer.unlock();
        }
    }
}
