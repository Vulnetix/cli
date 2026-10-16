package com.acme.auth;

import org.springframework.security.crypto.password.PasswordEncoder;

public class LoginService {
    private final PasswordEncoder passwordEncoder;

    public LoginService(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
    }

    public boolean login(AppUser user, String rawPassword) {
        if (passwordEncoder.matches(rawPassword, user.getPassword())) {
            return true;
        }
        return false;
    }
}
