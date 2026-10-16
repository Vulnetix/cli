package com.acme.core;

import java.util.Objects;

public final class Money {
    private final String currency;
    private final long cents;

    public Money(String currency, long cents) {
        this.currency = Objects.requireNonNull(currency, "currency");
        this.cents = cents;
    }

    public Money plus(Money other) {
        if (other == null) {
            throw new NullPointerException("other");
        }
        return new Money(currency, cents + other.cents);
    }

    public boolean isNpe(Throwable t) {
        return t instanceof NullPointerException;
    }
}
