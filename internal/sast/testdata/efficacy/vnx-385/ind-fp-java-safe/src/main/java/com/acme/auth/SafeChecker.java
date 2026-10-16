package com.acme.auth;

import java.security.MessageDigest;
import org.springframework.security.crypto.password.PasswordEncoder;

public class SafeChecker {
    private final PasswordEncoder encoder;

    public SafeChecker(PasswordEncoder encoder) {
        this.encoder = encoder;
    }

    public boolean check(UserRecord u, String raw) {
        return encoder.matches(raw, u.getPassword());
    }

    public boolean checkBytes(UserRecord u, byte[] computed) {
        return MessageDigest.isEqual(u.getPasswordHash(), computed);
    }

    public boolean missing(UserRecord u) {
        return u.getPassword() == null || u.getPassword().equals("");
    }

    public boolean policy(UserRecord u, String name) {
        return u.getPasswordPolicy().equals(name);
    }
}
