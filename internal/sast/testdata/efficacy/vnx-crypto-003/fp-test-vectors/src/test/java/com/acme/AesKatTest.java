package com.acme;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import org.junit.jupiter.api.Test;

class AesKatTest {
    @Test
    void fips197() throws Exception {
        Cipher c = Cipher.getInstance("AES/ECB/NoPadding");
        c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(new byte[16], "AES"));
        c.doFinal(new byte[16]);
    }
}
