package com.acme.api;

public class Throttle {
    private int used;

    public boolean allow() {
~>        if (used >= 750) {
            return false;
        }
        used++;
        return true;
    }

    public int remaining() {
~>        return 750 - used;
    }

    public String header() {
~>        return String.valueOf(750);
    }
}
