package com.acme.auth;

import java.util.Objects;

public class LoginService {
    public boolean login(String username, String password) {
        Account account = repo.findByUsername(username);
~>        if (account != null && account.getPassword().equals(password)) {
            return true;
        }
~>        return Objects.equals(password, account.getPassword());
    }

    boolean admin(String password) {
~>        return ADMIN_PASSWORD.equalsIgnoreCase(password);
    }
}
