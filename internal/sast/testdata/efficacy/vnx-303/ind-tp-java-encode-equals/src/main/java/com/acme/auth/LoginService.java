package com.acme.auth;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class LoginService {
    private final PasswordEncoder passwordEncoder;
    private final UserRepository users;

    public LoginService(PasswordEncoder passwordEncoder, UserRepository users) {
        this.passwordEncoder = passwordEncoder;
        this.users = users;
    }

    public boolean login(String username, String rawPassword) {
        AppUser user = users.findByUsername(username).orElse(null);
        if (user == null) {
            return false;
        }
~>        return passwordEncoder.encode(rawPassword).equals(user.getPassword());
    }
}
