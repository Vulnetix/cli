package com.acme.util;

public class Holder {
    private static final Service INSTANCE = new Service();

    static Service create() {
        return new Service();
    }

    static class Lazy {
        static final Service VALUE = new Service();
    }

    public static synchronized Service get() {
        return new Service();
    }
}
