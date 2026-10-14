package com.example.crypto;

import java.nio.charset.StandardCharsets;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

public class TokenCipher {
    private static final String ENCRYPTION_KEY = "Sup3rS3cretK3y!!";
    private static final byte[] HMAC_KEY = "another-static-key".getBytes(StandardCharsets.UTF_8);

    public byte[] encrypt(byte[] plain) throws Exception {
~>        SecretKeySpec spec = new SecretKeySpec(ENCRYPTION_KEY.getBytes(StandardCharsets.UTF_8), "AES");
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, spec);
        return cipher.doFinal(plain);
    }

    public SecretKeySpec hmac() {
~>        return new SecretKeySpec(HMAC_KEY, "HmacSHA256");
    }

    public SecretKeySpec local() {
        String k = "local-key-value!";
        byte[] kb = k.getBytes(StandardCharsets.UTF_8);
~>        return new SecretKeySpec(kb, "AES");
    }
}
