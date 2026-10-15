package com.acme.auth;

public class LoginService {
    private final UserRepository users;

    public LoginService(UserRepository users) {
        this.users = users;
    }

    public User login(String name) {
~>        User u = users.findByUsername(name).get();
~>        User v = users.findOneByEmailIgnoreCase(name.trim()).get();
        return u != null ? u : v;
    }
}
