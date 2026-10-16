package com.acme;

import java.security.SecureRandom;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;

public class Good {
    private static final SecureRandom RNG = new SecureRandom();

    byte[] enc(SecretKey k, byte[] p) throws Exception {
        byte[] iv = new byte[12];
        RNG.nextBytes(iv);
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        c.init(Cipher.ENCRYPT_MODE, k, new GCMParameterSpec(128, iv));
        return c.doFinal(p);
    }

    byte[] dec(SecretKey k, byte[] msg) throws Exception {
        byte[] iv = new byte[16];
        System.arraycopy(msg, 0, iv, 0, 16);
        Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
        c.init(Cipher.DECRYPT_MODE, k, new IvParameterSpec(iv));
        return c.doFinal(msg, 16, msg.length - 16);
    }
}
