package com.example;

import java.util.concurrent.atomic.AtomicReference;

public class Lazy {
    private static class Holder {
        static final Lazy INSTANCE = new Lazy();
    }

    public static Lazy get() {
        return Holder.INSTANCE;
    }

    private final AtomicReference<String> value = new AtomicReference<>();

    public String value() {
        if (value.get() == null) {
            synchronized (value) {
                if (value.get() == null) {
                    value.set("v");
                }
            }
        }
        return value.get();
    }
}
