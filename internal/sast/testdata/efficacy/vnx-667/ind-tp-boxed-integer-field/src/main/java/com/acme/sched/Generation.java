package com.acme.sched;

public class Generation {
    private Integer generation = 0;

    public int bump() {
~>        synchronized (generation) {
            generation++;
            return generation;
        }
    }
}
