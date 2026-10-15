package com.acme.billing;

public class Account {
    protected long balance;

    public static Account open(boolean premium) {
~>        return premium ? new PremiumAccount() : new Account();
    }

    public long limit() {
~>        PremiumAccount p = (PremiumAccount) this;
        return p.overdraft();
    }
}
