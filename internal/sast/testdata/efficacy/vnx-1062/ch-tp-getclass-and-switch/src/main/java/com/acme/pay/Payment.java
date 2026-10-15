package com.acme.pay;

public abstract class Payment {
    protected long cents;

    public String channel() {
~>        if (getClass() == CardPayment.class) {
            return "card";
        }
        return switch (this) {
~>            case BankPayment bank -> "bank:" + bank.iban();
            default -> "other";
        };
    }
}
