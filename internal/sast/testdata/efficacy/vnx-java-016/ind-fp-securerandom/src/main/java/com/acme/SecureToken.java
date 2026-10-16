package com.acme;

import java.security.SecureRandom;
import java.util.Base64;

public class SecureToken {
    private static final SecureRandom RNG = new SecureRandom();

    public String newToken() {
        byte[] b = new byte[32];
        RNG.nextBytes(b);
        String sessionToken = Base64.getUrlEncoder().withoutPadding().encodeToString(b);
        return sessionToken;
    }

    public byte[] salt() {
        byte[] salt = new byte[16];
        new SecureRandom().nextBytes(salt);
        return salt;
    }
}
