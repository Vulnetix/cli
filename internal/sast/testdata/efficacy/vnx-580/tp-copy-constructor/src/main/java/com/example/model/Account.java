package com.example.model;

public class Account implements Cloneable {
    private String owner;
    private long balance;

    public Account(Account other) {
        this.owner = other.owner;
        this.balance = other.balance;
    }

    @Override
~>    public Account clone() {
        return new Account(this);
    }
}
