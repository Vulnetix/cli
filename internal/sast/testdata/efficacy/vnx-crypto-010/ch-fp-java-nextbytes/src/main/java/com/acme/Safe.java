package com.acme;

import java.security.SecureRandom;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;

public class Safe {
    private static final SecureRandom RNG = new SecureRandom();

    public byte[] encrypt(SecretKey key, byte[] data) throws Exception {
        byte[] iv = new byte[16];
        RNG.nextBytes(iv);
        Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
        c.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));
        return c.doFinal(data);
    }

    public byte[] decryptGcm(SecretKey key, byte[] blob) throws Exception {
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        c.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(128, blob, 0, 12));
        return c.doFinal(blob, 12, blob.length - 12);
    }

    public PBEKeySpec spec(char[] pw, byte[] userSalt) {
        return new PBEKeySpec(pw, userSalt, 210000, 256);
    }
}
