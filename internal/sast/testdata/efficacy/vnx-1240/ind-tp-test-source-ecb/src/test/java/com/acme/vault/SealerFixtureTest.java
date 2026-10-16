package com.acme.vault;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import org.junit.jupiter.api.Test;

class SealerFixtureTest {
    @Test
    void legacyBlobDecrypts() throws Exception {
        byte[] key = new byte[16];
~>        Cipher fixture = Cipher.getInstance("AES/ECB/PKCS5Padding");
        fixture.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"));
        fixture.doFinal(new byte[16]);
    }
}
