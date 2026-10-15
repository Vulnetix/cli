package com.acme.auth;

public class LoginService {
    public boolean login(User user, String rawPassword) {
        return passwordEncoder.matches(rawPassword, user.getPassword());
    }

    public void register(User user, String rawPassword) {
        user.setPassword(passwordEncoder.encode(rawPassword));
        if (user.getName().equals("x")) {
            audit();
        }
    }
}
