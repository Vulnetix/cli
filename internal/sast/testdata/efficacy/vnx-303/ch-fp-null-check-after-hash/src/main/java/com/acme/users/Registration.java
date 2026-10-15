package com.acme.users;

import org.springframework.security.crypto.password.PasswordEncoder;

public class Registration {
    private final PasswordEncoder passwordEncoder;
    private final UserRepository users;

    public Registration(PasswordEncoder passwordEncoder, UserRepository users) {
        this.passwordEncoder = passwordEncoder;
        this.users = users;
    }

    public User register(String email, String raw) {
        String hashed = passwordEncoder.encode(raw);
        if (hashed == null || hashed.isEmpty()) {
            throw new IllegalStateException("encoder failed");
        }
        return users.save(new User(email, hashed));
    }
}
