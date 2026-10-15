package com.acme;

import java.security.SecureRandom;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;

public class TokenCipher {
    private final SecureRandom random = new SecureRandom();
    private final byte[] iv = new byte[12];

    public byte[] encrypt(SecretKey key, byte[] data) throws Exception {
        random.nextBytes(iv);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, iv));
        return cipher.doFinal(data);
    }
}
