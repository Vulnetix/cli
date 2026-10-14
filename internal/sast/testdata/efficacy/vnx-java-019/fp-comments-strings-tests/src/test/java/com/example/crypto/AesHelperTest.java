package com.example.crypto;

import javax.crypto.spec.SecretKeySpec;
import org.junit.jupiter.api.Test;

class AesHelperTest {
    @Test
    void roundTrip() {
        SecretKeySpec spec = new SecretKeySpec("0123456789abcdef".getBytes(), "AES");
    }
}
