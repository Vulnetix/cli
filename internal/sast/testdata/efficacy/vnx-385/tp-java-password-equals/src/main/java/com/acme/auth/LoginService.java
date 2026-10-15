package com.acme.auth;

import java.util.Arrays;
import java.util.Objects;

public class LoginService {
    private final UserRepository repo;

    public LoginService(UserRepository repo) {
        this.repo = repo;
    }

    public boolean login(String name, String password) {
        User u = repo.find(name);
~>        return u != null && u.getPassword().equals(password);
    }

    public boolean loginHash(String name, byte[] candidate) {
        User u = repo.find(name);
~>        return Arrays.equals(u.getPasswordHash(), digest(candidate));
    }

    public boolean same(String typed, User u) {
~>        if (typed.equals(u.getPassword())) {
            return true;
        }
~>        return Objects.equals(u.passwordHash, hash(typed));
    }
}
