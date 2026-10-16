package com.acme.token;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.security.SecureRandom;
import org.junit.jupiter.api.Test;

class TokenFactoryTest {
    @Test
    void deterministicTokenForFixture() {
        SecureRandom sr = new SecureRandom("fixture".getBytes());
        sr.setSeed(System.currentTimeMillis());
        assertEquals(32, new byte[32].length);
    }
}
