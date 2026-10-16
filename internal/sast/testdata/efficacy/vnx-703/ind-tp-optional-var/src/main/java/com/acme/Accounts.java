package com.acme;

import java.util.Optional;

public class Accounts {
    private final AccountRepo repo;
    Accounts(AccountRepo repo) { this.repo = repo; }

    String email(String login) {
        Optional<Account> account = repo.findByLogin(login);
        log(login);
~>        return account.get().getEmail();
    }
}
