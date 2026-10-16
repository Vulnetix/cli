package com.acme.cache;

public class Immutable implements Cloneable {
    private final String key;

    public Immutable(String key) {
        this.key = key;
    }

    @Override
    public Immutable clone() {
        return this;
    }
}
