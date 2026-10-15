package com.acme;

public class AuthService {
    public boolean authenticate(User user, String rawPassword) {
        if (!passwordEncoder.matches(rawPassword, user.getPassword())) {
            return false;
        }
        return user.getPasswordHash() != null;
    }
}
