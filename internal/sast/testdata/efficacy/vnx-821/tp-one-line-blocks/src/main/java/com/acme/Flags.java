package com.acme;

public class Flags {
    private final Boolean ready = Boolean.FALSE;
    private int n;

    public void touch() {
~>        synchronized (ready) { n++; }
~>        synchronized (new Object()) { n--; }
        synchronized (this) { n++; }
    }
}
