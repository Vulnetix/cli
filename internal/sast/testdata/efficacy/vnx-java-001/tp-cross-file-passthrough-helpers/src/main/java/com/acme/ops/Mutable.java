package com.acme.ops;

public class Mutable {
    private String value;

    public Mutable(String value) {
        this.value = value;
    }

    public void set(String value) {
        this.value = value;
    }

    public String get() {
        return value;
    }
}
