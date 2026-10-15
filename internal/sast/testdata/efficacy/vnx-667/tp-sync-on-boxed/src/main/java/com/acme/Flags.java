package com.acme;

public class Flags {
    private Boolean ready = Boolean.FALSE;
    private Integer generation = 0;

    void markReady() {
~>        synchronized (ready) {
            ready = Boolean.TRUE;
        }
    }

    void bump() {
~>        synchronized (this.generation) {
            generation++;
        }
    }

    void global() {
~>        synchronized (Boolean.TRUE) {
            reset();
        }
    }
}
