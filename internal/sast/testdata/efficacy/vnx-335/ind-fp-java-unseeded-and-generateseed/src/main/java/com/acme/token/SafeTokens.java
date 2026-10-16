package com.acme.token;

import java.security.SecureRandom;
import java.util.Base64;

public class SafeTokens {
    private final SecureRandom random = new SecureRandom();

    public SafeTokens() {
        random.setSeed(random.generateSeed(32));
    }

    public String token() {
        byte[] buf = new byte[32];
        random.nextBytes(buf);
        return Base64.getUrlEncoder().encodeToString(buf);
    }
}
