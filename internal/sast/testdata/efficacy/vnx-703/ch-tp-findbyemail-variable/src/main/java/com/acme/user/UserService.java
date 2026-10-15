package com.acme.user;

import java.util.Optional;

public class UserService {
    private final UserRepository repo;

    public UserService(UserRepository repo) {
        this.repo = repo;
    }

    public String email(String login) {
        Optional<User> found = repo.findByLogin(login);
~>        return found.get().getEmail();
    }
}
