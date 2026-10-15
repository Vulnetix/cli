package com.acme;

public class Widget {
    private final Engine engine;

    {
        engine = new Engine();
    }

    public static Widget create() {
        return new Widget();
    }

    static Widget lazy;

    static Widget get() {
        if (lazy == null) {
            lazy = new Widget();
        }
        return lazy;
    }
}
