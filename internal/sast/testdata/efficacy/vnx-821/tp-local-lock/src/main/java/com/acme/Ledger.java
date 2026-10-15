package com.acme;

public class Ledger {
    private long balance;

    public void deposit(long amount) {
        Object lock = new Object();
~>        synchronized (lock) {
            balance += amount;
        }
    }
}
