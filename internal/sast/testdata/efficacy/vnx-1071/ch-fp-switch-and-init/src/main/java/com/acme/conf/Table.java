package com.acme.conf;

public class Table {
    private static final int[] EMPTY = {};
    private final Runnable noop = () -> {};

    public String name(int code) {
        switch (code) {
            case 1:
                return "one";
            default:
                return "other";
        }
    }

    static {
        System.setProperty("acme.table", "on");
    }
}
