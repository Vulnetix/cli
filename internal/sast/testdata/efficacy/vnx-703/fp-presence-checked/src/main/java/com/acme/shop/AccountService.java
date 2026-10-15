package com.acme.shop;

import java.util.Optional;

public class AccountService {
    public String email(String login) {
        Optional<Account> account = repo.findByLogin(login);
        if (!account.isPresent()) {
            throw new IllegalArgumentException("no account");
        }
        return account.get().getEmail();
    }

    public String name(String login) {
        Optional<Account> a = repo.findByLogin(login);
        if (a.isEmpty()) {
            return "";
        }
        return a.get().getName();
    }

    public String other(String login) {
        Optional<Account> b = repo.findByLogin(login);
        return b.isPresent() ? b.get().getName() : "";
    }
}
