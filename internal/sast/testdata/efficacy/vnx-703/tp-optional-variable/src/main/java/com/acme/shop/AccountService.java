package com.acme.shop;

import java.util.Optional;

public class AccountService {
    private final AccountRepository repo;

    AccountService(AccountRepository repo) { this.repo = repo; }

    public String email(String login) {
        Optional<Account> account = repo.findByLogin(login);
        audit(login);
~>        return account.get().getEmail();
    }
}
