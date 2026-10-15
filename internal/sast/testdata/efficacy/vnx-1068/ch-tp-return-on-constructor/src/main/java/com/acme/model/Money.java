package com.acme.model;

public final class Money {
    private final long cents;

    /**
     * Creates an amount.
     *
     * @param cents the amount in cents
     * @return a new Money
     */
~>    Money(long cents) {
        this.cents = cents;
    }
}
