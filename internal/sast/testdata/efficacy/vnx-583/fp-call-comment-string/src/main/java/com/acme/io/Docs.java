package com.acme.io;

public class Docs {
    // public void finalize() is a bad idea
    private static final String NOTE = "public void finalize() should be protected";

    void run(Stream s) {
        s.finalizeOrder();
    }
}
