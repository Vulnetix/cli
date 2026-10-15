package com.acme;

import java.security.SecureRandom;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;

public class TokenCipher {
    private static final byte[] IV = new byte[12];

    static {
        new SecureRandom().nextBytes(IV);
    }

    public byte[] encrypt(SecretKey key, byte[] data) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
~>        cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, IV));
        return cipher.doFinal(data);
    }
}
