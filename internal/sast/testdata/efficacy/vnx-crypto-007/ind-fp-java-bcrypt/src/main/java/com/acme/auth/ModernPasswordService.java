package com.acme.auth;

import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

public class ModernPasswordService {
    private final BCryptPasswordEncoder encoder = new BCryptPasswordEncoder(12);

    public String hash(String password) {
        return encoder.encode(password);
    }
}
