package com.acme.model;

public final class Money implements Cloneable {
    private long cents;

    @Override
    public Money clone() {
        try {
            return (Money) super.clone();
        } catch (CloneNotSupportedException e) {
            throw new AssertionError(e);
        }
    }
}
