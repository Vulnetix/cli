package com.acme.auth;

public class Auth {
    private final PasswordEncoder encoder;

    public boolean authenticate(String username, String password) {
        User user = users.find(username);
        if (user == null) {
            return false;
        }
        return encoder.matches(password, user.getHash());
    }

    public boolean supports(Class<?> authentication) {
        return true;
    }

    public boolean isEnabled() { return true; }
}
