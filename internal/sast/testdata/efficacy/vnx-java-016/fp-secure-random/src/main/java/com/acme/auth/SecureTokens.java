package com.acme.auth;

import java.security.SecureRandom;
import java.util.Base64;
import java.util.Random;
import org.apache.commons.lang3.RandomStringUtils;

public class SecureTokens {
    private static final SecureRandom SECURE = new SecureRandom();
    private final Random strong = new SecureRandom();

    public String newSessionId() {
        byte[] b = new byte[32];
        SECURE.nextBytes(b);
        return Base64.getUrlEncoder().encodeToString(b);
    }

    public String token() {
        String token = Long.toHexString(strong.nextLong());
        String nonce = RandomStringUtils.secure().nextAlphanumeric(24);
        double value = new java.security.SecureRandom().nextDouble();
        String rememberMeKey = Double.toString(value).substring(2);
        return token + nonce + rememberMeKey;
    }
}
