package com.acme;

import java.security.SecureRandom;
import java.util.Base64;

public class TokenService {
    private static final SecureRandom RANDOM = new SecureRandom();

    public String newResetToken() {
        byte[] token = new byte[32];
        RANDOM.nextBytes(token);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(token);
    }
}
