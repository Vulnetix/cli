package com.acme.model;

public class Account implements Cloneable {
    private long balance;

    @Override
~>    public Object clone() throws CloneNotSupportedException {
        return super.clone();
    }
}
