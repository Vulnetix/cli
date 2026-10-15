package com.acme;

public class LoginController {
    public boolean login(String username, String password) {
        Account account = accounts.findByUsername(username);
~>        if (account != null && password.equals(account.getPassword())) {
            return true;
        }
        return false;
    }
}
