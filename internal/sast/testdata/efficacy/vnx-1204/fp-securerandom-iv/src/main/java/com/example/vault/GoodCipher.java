package com.example.vault;

import java.security.SecureRandom;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;

public class GoodCipher {
    private static final SecureRandom RANDOM = new SecureRandom();
    private final SecureRandom random = SecureRandom.getInstanceStrong();

    byte[] enc(Cipher c, javax.crypto.SecretKey key, byte[] in) throws Exception {
        byte[] iv = new byte[16];
        RANDOM.nextBytes(iv);
        c.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));
        return c.doFinal(in);
    }

    byte[] seal(Cipher c, javax.crypto.SecretKey key, byte[] in) throws Exception {
        byte[] nonce = new byte[12];
        random.nextBytes(nonce);
        c.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, nonce));
        return c.doFinal(in);
    }

    byte[] seal2(Cipher c, javax.crypto.SecretKey key, byte[] in) throws Exception {
        byte[] iv = new byte[12];
        new SecureRandom().nextBytes(iv);
        c.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, iv));
        return c.doFinal(in);
    }
}
