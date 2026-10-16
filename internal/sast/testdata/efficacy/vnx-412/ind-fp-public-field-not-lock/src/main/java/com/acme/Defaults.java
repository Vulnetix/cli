package com.acme;

import java.util.concurrent.atomic.AtomicLong;

public class Defaults {
    public static final Object NONE = new Object();
    public static final String REGION = "eu-west-1";
    public final AtomicLong hits = new AtomicLong();

    public Object orNone(Object value) {
        return value == null ? NONE : value;
    }
}
