package com.acme;

public class Notes {
    // static { instance = new Notes(); } was removed
    static final String HELP = "static { x = new Foo(); }";

    static {
        // new Service() is created lazily now
        System.loadLibrary("native");
    }
}
