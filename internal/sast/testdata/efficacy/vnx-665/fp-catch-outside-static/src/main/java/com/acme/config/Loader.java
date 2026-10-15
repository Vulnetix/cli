package com.acme.config;

public class Loader {
    private static final String DEFAULT = "x";

    static {
        System.loadLibrary("native");
    }

    public void load() {
        try {
            run();
        } catch (Exception e) {
        }
    }
}
