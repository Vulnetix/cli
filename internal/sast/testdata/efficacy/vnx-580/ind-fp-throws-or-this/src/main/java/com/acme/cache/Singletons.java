package com.acme.cache;

public class Singletons implements Cloneable {
    private static final Singletons INSTANCE = new Singletons();

    @Override
    protected Object clone() throws CloneNotSupportedException {
        throw new CloneNotSupportedException("singleton");
    }
}
