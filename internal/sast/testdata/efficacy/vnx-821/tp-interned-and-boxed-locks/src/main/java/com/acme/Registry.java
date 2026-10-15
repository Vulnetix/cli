package com.acme;

public class Registry {
    private final String LOCK = "LOCK";
    private final Integer count = 0;
    private int size;

    public void add() {
~>        synchronized (LOCK) {
            size++;
        }
~>        synchronized ("cache") {
            size++;
        }
~>        synchronized (count) {
            size++;
        }
~>        synchronized (Boolean.TRUE) {
            size++;
        }
    }
}
