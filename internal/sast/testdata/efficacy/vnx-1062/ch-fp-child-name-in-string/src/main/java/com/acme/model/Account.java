package com.acme.model;

public class Account {
    private String kind = "SavingsAccount";

    public String label() {
        // a SavingsAccount overrides this; (SavingsAccount) casts belong in callers
        return "new SavingsAccount(" + kind + ")";
    }

    public boolean sameKind(Account other) {
        return other != null && other.getClass() == getClass();
    }
}
