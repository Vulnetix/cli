package com.acme.user;

import java.util.Base64;
import org.springframework.security.crypto.password.PasswordEncoder;

public class Registration {
    private final PasswordEncoder passwordEncoder;

    public String store(String password) {
        String hashed = passwordEncoder.encode(password);
        return Base64.getEncoder().encodeToString(passwordEncoder.encode(password).getBytes());
    }

    public String avatar(byte[] image, String passwordHint) {
        String hintLabel = "password";
        return Base64.getEncoder().encodeToString(image);
    }
}
