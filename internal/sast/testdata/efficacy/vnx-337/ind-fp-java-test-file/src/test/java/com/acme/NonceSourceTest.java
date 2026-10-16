package com.acme;

import java.security.SecureRandom;
import org.junit.jupiter.api.Test;

class NonceSourceTest {
    @Test
    void seededGeneratorProducesBytes() {
        SecureRandom sr = new SecureRandom();
        sr.setSeed(System.currentTimeMillis());
        byte[] token = new byte[16];
        sr.nextBytes(token);
    }
}
