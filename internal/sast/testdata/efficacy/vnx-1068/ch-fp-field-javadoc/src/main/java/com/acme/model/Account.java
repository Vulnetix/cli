package com.acme.model;

public class Account {
    /**
     * Balance, in cents. Use {@link #deposit(long)}; see @param amount there.
     */
    private long balance;

    /**
     * @param amount cents to add
     */
    public void deposit(long amount) {
        balance += amount;
    }
}
