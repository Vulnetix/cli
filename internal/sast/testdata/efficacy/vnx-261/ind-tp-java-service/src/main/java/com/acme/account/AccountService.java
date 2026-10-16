package com.acme.account;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class AccountService {
    private final AccountRepository repo;

    public AccountService(AccountRepository repo) {
        this.repo = repo;
    }

    public void changePassword(long id, String newPassword) {
        Account a = repo.findById(id);
~>        String stored = Base64.getEncoder().encodeToString(newPassword.getBytes(StandardCharsets.UTF_8));
        a.setCredential(stored);
        repo.save(a);
    }
}
