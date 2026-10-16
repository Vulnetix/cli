package com.acme.auth;

import org.springframework.security.crypto.password.PasswordEncoder;

public class SecureLogin {
    private final PasswordEncoder passwordEncoder;

    public SecureLogin(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
    }

    public boolean check(Account account, String password) {
        return passwordEncoder.matches(password, account.getPassword());
    }

    public boolean isReuse(String newPassword, String currentPassword) {
        return newPassword.equals(currentPassword);
    }
}
