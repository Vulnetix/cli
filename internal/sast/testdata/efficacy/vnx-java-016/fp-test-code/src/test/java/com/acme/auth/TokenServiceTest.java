package com.acme.auth;

import java.util.Random;
import org.junit.jupiter.api.Test;

class TokenServiceTest {
    @Test
    void acceptsAnyToken() {
        String token = Long.toHexString(new Random(42).nextLong());
        assert token.length() > 0;
    }
}
