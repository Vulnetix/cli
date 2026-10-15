package com.acme;

public class Store {
    private final Object lock = new Object();

    public void save() {
        try {
            write();
~>        } finally {
        }
~>        synchronized (lock) {
        }
~>        try {
        } catch (RuntimeException e) {
            throw e;
        }
    }

    private void write() {}
}
