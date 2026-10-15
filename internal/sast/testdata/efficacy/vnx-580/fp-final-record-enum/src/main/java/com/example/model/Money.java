package com.example.model;

public final class Money implements Cloneable {
    private final long cents;

    public Money(long cents) {
        this.cents = cents;
    }

    @Override
    public Money clone() {
        return new Money(cents);
    }

    public static final class Rate implements Cloneable {
        double v;

        @Override
        public Rate clone() {
            Rate r = new Rate();
            r.v = v;
            return r;
        }
    }
}
