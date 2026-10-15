package com.acme;

public class Safe {
    private final Object lock = new Object();
    private final String name;

    Safe(String name) { this.name = name; }

    public void a() {
        synchronized (lock) {
            work();
        }
    }

    public void b() {
        synchronized (this) {
            work();
        }
    }

    public void c() {
        synchronized (Safe.class) {
            work();
        }
    }

    public synchronized void d(String message) {
        log(message);
    }
}
