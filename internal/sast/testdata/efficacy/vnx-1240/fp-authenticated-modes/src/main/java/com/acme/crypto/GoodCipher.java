package com.acme.crypto;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

public class GoodCipher {
    private static final String TRANSFORMATION = "AES/GCM/NoPadding";

    public byte[] seal(SecretKey key, byte[] iv, byte[] plain) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, iv));
        return cipher.doFinal(plain);
    }

    public byte[] sealConst(SecretKey key, byte[] iv, byte[] plain) throws Exception {
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, iv));
        return cipher.doFinal(plain);
    }

    public Cipher chacha() throws Exception {
        return Cipher.getInstance("ChaCha20-Poly1305");
    }

    public Cipher configured(String transformation) throws Exception {
        return Cipher.getInstance(transformation);
    }
}
