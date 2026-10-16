package com.acme.auth;

public class LoginService {
    private final AccountRepository accounts;

    public LoginService(AccountRepository accounts) {
        this.accounts = accounts;
    }

    public boolean authenticate(String username, String password) {
        Account account = accounts.findByUsername(username);
~>        return account != null && account.getPassword().equals(password);
    }
}
