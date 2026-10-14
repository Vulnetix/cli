package com.example.crypto;

import java.security.SecureRandom;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;

public class ModernBox {
    private static final SecureRandom RNG = new SecureRandom();
    private static final int IV_LEN = 12;

    public byte[] seal(SecretKey key, byte[] data) throws Exception {
        byte[] iv = new byte[IV_LEN];
        RNG.nextBytes(iv);
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        c.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, iv));
        return c.doFinal(data);
    }

    public IvParameterSpec cbc() {
        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);
        return new IvParameterSpec(iv);
    }

    public IvParameterSpec generated() throws Exception {
        Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
        return new IvParameterSpec(c.getIV());
    }
}
