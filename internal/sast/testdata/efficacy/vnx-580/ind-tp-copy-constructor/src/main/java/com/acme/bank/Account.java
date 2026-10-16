package com.acme.bank;

import java.math.BigDecimal;

public class Account implements Cloneable {
    private final String iban;
    private BigDecimal balance;

    public Account(String iban, BigDecimal balance) {
        this.iban = iban;
        this.balance = balance;
    }

    protected Account(Account other) {
        this(other.iban, other.balance);
    }

    @Override
~>    public Account clone() {
        return new Account(this);
    }
}
