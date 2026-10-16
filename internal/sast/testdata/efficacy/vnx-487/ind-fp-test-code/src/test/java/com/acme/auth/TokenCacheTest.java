package com.acme.auth;

import org.junit.jupiter.api.Test;

class TokenCacheTest {
    String accessToken = "test-access";
    char[] password = "changeit".toCharArray();

    @Test
    void updates() {
        TokenCache c = new TokenCache();
        c.update(accessToken, "r", java.time.Instant.now());
    }
}
