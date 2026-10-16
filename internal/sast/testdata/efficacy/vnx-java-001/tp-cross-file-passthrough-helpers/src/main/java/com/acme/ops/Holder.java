package com.acme.ops;

public class Holder {
    private final String value;

    public Holder(String value) {
        this.value = value;
    }

    public String get() {
        return value;
    }
}
