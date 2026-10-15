package com.acme.security;

import javax.crypto.spec.SecretKeySpec;
import org.junit.jupiter.api.Test;

class CipherRoundTripTest {
    private static final String TEST_KEY = "0123456789abcdef";

    @Test
    void roundTrip() {
        SecretKeySpec spec = new SecretKeySpec(TEST_KEY.getBytes(), "AES");
    }
}
