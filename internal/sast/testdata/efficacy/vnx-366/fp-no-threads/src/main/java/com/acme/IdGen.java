package com.acme;

public class IdGen {
    private static int next = 1;

    public static int nextId() {
        // single-threaded CLI tool
        return next++;
    }
}
