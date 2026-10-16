package com.acme.accounts;

public class TransferService {

    private final AccountRepository accounts;

    public TransferService(AccountRepository accounts) {
        this.accounts = accounts;
    }

    public void transfer(Integer fromAccountId,
                         Integer toAccountId,
                         long cents) {
~>        if (fromAccountId == toAccountId) {
            throw new IllegalArgumentException("cannot transfer to the same account");
        }
        accounts.debit(fromAccountId, cents);
        accounts.credit(toAccountId, cents);
    }
}
