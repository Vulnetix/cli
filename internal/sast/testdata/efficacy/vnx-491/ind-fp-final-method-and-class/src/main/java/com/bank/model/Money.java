package com.bank.model;

public class Money implements Cloneable {
    private long cents;

    @Override
    public final Money clone() {
        try {
            return (Money) super.clone();
        } catch (CloneNotSupportedException e) {
            throw new AssertionError(e);
        }
    }
}

final class Rate implements Cloneable {
    private double value;

    @Override
    public Object clone() throws CloneNotSupportedException {
        return super.clone();
    }
}
