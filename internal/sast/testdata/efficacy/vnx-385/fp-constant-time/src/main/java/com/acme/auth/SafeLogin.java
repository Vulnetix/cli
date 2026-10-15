package com.acme.auth;

import java.security.MessageDigest;

public class SafeLogin {
    public boolean check(User u, byte[] candidate, PasswordEncoder encoder, String raw) {
        if (u.getPassword() == null || u.getPassword().equals("")) {
            return false;
        }
        if (encoder.matches(raw, u.getPassword())) {
            return true;
        }
        return MessageDigest.isEqual(u.getPasswordHash(), digest(candidate));
    }
}
