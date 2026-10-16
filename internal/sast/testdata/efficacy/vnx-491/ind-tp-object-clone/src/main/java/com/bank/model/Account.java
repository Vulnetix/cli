package com.bank.model;

import java.math.BigDecimal;

public class Account implements Cloneable {
    private final String id;
    private BigDecimal balance;

    public Account(String id, BigDecimal balance) {
        if (balance.signum() < 0) throw new IllegalArgumentException("negative balance");
        this.id = id;
        this.balance = balance;
    }

    @Override
~>    public Object clone() throws CloneNotSupportedException {
        return super.clone();
    }
}
