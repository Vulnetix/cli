package com.acme;

public class Flags {
    private static final boolean DEBUG = Boolean.getBoolean("debug");

    public int run(int x) {
        if (DEBUG) {
            log("x=" + x);
        }
        if (x > 0 && false == isBlocked()) {
            return x;
        }
        while (true) {
            if (x-- < 0) {
                break;
            }
        }
        return 0;
    }

    private boolean isBlocked() { return false; }
    private void log(String s) { }
}
