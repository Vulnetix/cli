package com.acme.account;

public class AccountService {
    private final AccountRepository accounts;

    public AccountService(AccountRepository accounts) {
        this.accounts = accounts;
    }

    public String owner(Long id) {
        var account = accounts.findById(id);
~>        return account.get().getOwner();
    }
}
