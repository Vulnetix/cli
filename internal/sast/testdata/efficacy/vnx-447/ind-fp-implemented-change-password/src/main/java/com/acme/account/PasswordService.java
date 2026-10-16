package com.acme.account;

import org.springframework.security.crypto.password.PasswordEncoder;

public class PasswordService {

    private final UserRepository users;
    private final PasswordEncoder encoder;

    public PasswordService(UserRepository users, PasswordEncoder encoder) {
        this.users = users;
        this.encoder = encoder;
    }

    public boolean changePassword(long userId, String oldPassword, String newPassword) {
        User user = users.findById(userId).orElseThrow();
        if (!encoder.matches(oldPassword, user.getPasswordHash())) {
            return false;
        }
        user.setPasswordHash(encoder.encode(newPassword));
        users.save(user);
        return true;
    }
}
