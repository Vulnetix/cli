package com.acme.token;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;

public class TokenFactory {
~>    private final SecureRandom random = new SecureRandom("acme-token-seed".getBytes(StandardCharsets.UTF_8));

    public String newToken() {
        byte[] buf = new byte[32];
        random.nextBytes(buf);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(buf);
    }
}
