package com.example.auth;

import org.mindrot.jbcrypt.BCrypt;
import org.springframework.security.crypto.password.PasswordEncoder;

public class LoginService {
    private final PasswordEncoder passwordEncoder;

    public LoginService(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
    }

    public Session login(User user, String candidate) {
~>        BCrypt.checkpw(candidate, user.getHash());
        return Session.issue(user);
    }

    public Session loginV2(User user, String candidate) {
~>        passwordEncoder.matches(candidate, user.getHash());
        return Session.issue(user);
    }
}
