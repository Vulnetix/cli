package com.acme;

public class Accounts {
    public void debit(int accountId, long cents) {
~>        synchronized (Integer.valueOf(accountId)) {
            Ledger.debit(accountId, cents);
        }
    }

    public void toggle() {
~>        synchronized (Boolean.TRUE) {
            Flags.flip();
        }
    }
}
